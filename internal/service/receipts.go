package service

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"regexp"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/paulmalmquist/storage_relspace/internal/errs"
)

// Operation receipts make retried mutations safe when a response is lost.
//
// A receipt is keyed by (app, subject, actor, op_id): the same client-chosen ID used by an agent on
// a user's behalf and by the user directly are different operations. It stores a keyed fingerprint
// (HMAC under a per-app receipt key) of the operation type, target, expected version, marking and a
// digest of the canonical payload. Reusing an op_id for a different operation is a conflict; the
// keyed fingerprint means a database reader cannot confirm guesses of low-entropy payloads.
//
// The receipt is resolved before any precondition: a retried update whose first attempt succeeded
// returns that result even though the record has moved past the expected version. A replay is
// re-authorized under current policy, so a receipt never outlives a revocation.

var opIDPattern = regexp.MustCompile(`^[A-Za-z0-9._:~-]{8,128}$`)

// ValidOpID reports whether s may be used as an operation ID.
func ValidOpID(s string) bool { return opIDPattern.MatchString(s) }

const receiptTTL = 7 * 24 * time.Hour

// Operation describes a mutation for fingerprinting.
type Operation struct {
	Type            string // record.create, record.update, ...
	Target          string // collection/id, blob, ...
	ExpectedVersion int
	Marking         string
	Payload         any // canonicalized with sorted keys
}

// Receipt is a stored operation outcome.
type Receipt struct {
	OpID            string         `json:"op_id"`
	Type            string         `json:"op_type"`
	Status          string         `json:"status"`
	ResourceType    string         `json:"resource_type,omitempty"`
	ResourceID      string         `json:"resource_id,omitempty"`
	ResourceVersion int            `json:"resource_version,omitempty"`
	Result          map[string]any `json:"result"`
	CreatedAt       time.Time      `json:"created_at"`
	CompletedAt     *time.Time     `json:"completed_at,omitempty"`
}

type receipts struct {
	core *Core
	keys *Keys
}

func (r *receipts) fingerprint(ctx context.Context, tx pgx.Tx, app string, op Operation) ([]byte, string, error) {
	keyID, key, err := r.keys.Active(ctx, tx, app, "receipts", PurposeReceipt)
	if err != nil {
		return nil, "", err
	}
	payload, err := json.Marshal(op.Payload) // map keys are sorted by encoding/json
	if err != nil {
		return nil, "", err
	}
	digest := sha256.Sum256(payload)
	canonical, _ := json.Marshal([]any{"strongbox/receipt/v1", app, op.Type, op.Target, op.ExpectedVersion, op.Marking, digest[:]})
	m := hmac.New(sha256.New, key)
	m.Write(canonical)
	return m.Sum(nil), keyID, nil
}

// claim registers c.OpID for op in tx. It returns (nil, nil) when there is no op ID, the stored
// receipt when the operation already succeeded (replay), and an error when the ID was used for a
// different operation or the operation is still running elsewhere. On a fresh claim it returns
// (nil, nil) as well and the caller must call complete in the same transaction.
//
// Two concurrent first attempts serialize on the primary key: the second waits for the first
// transaction, then sees its committed receipt (or claims it if the first rolled back).
func (r *receipts) claim(ctx context.Context, tx pgx.Tx, c Ctx, op Operation, lease time.Duration, leaseOwner string) (*Receipt, error) {
	if c.OpID == "" {
		return nil, nil
	}
	if !ValidOpID(c.OpID) {
		return nil, errs.Invalid("Idempotency-Key must be 8-128 characters of [A-Za-z0-9._:~-]")
	}
	fp, keyID, err := r.fingerprint(ctx, tx, c.App, op)
	if err != nil {
		return nil, err
	}
	var leaseExpires *time.Time
	var owner *string
	if lease > 0 {
		t := time.Now().Add(lease)
		leaseExpires, owner = &t, &leaseOwner
	}
	tag, err := tx.Exec(ctx, `INSERT INTO operation_receipts (app, subject, actor, op_id, op_type, fingerprint, fp_key_id,
		status, lease_owner, lease_expires, expires_at) VALUES ($1,$2,$3,$4,$5,$6,$7,'pending',$8,$9,$10)
		ON CONFLICT DO NOTHING`, c.App, c.Principal.Subject, c.Actor(), c.OpID, op.Type, fp, keyID, owner, leaseExpires,
		time.Now().Add(receiptTTL))
	if err != nil {
		return nil, err
	}
	if tag.RowsAffected() == 1 {
		return nil, nil
	}
	var storedFP []byte
	var storedType, status string
	var leaseUntil *time.Time
	rc := &Receipt{OpID: c.OpID}
	var resType, resID *string
	var resVersion *int
	err = tx.QueryRow(ctx, `SELECT op_type, fingerprint, status, lease_expires, resource_type, resource_id, resource_version,
		result, created_at, completed_at FROM operation_receipts WHERE app = $1 AND subject = $2 AND actor = $3 AND op_id = $4
		FOR UPDATE`, c.App, c.Principal.Subject, c.Actor(), c.OpID).
		Scan(&storedType, &storedFP, &status, &leaseUntil, &resType, &resID, &resVersion, &rc.Result, &rc.CreatedAt, &rc.CompletedAt)
	if err != nil {
		return nil, err
	}
	if storedType != op.Type || !hmac.Equal(storedFP, fp) {
		return nil, errs.Coded(409, "idempotency_key_reused", "this Idempotency-Key was already used for a different operation")
	}
	rc.Type, rc.Status = storedType, status
	if resType != nil {
		rc.ResourceType = *resType
	}
	if resID != nil {
		rc.ResourceID = *resID
	}
	if resVersion != nil {
		rc.ResourceVersion = *resVersion
	}
	if status == "succeeded" {
		return rc, nil
	}
	// Pending: only long operations (uploads) hold a pending receipt across transactions.
	if leaseUntil != nil && leaseUntil.Before(time.Now()) {
		if _, err := tx.Exec(ctx, `UPDATE operation_receipts SET lease_owner = $5, lease_expires = $6
			WHERE app = $1 AND subject = $2 AND actor = $3 AND op_id = $4`, c.App, c.Principal.Subject, c.Actor(), c.OpID,
			leaseOwner, time.Now().Add(lease)); err != nil {
			return nil, err
		}
		rc.Status = "taken_over"
		return rc, nil
	}
	return nil, errs.Coded(409, "operation_in_progress", "an operation with this Idempotency-Key is still in progress; retry later")
}

// complete marks the claimed receipt succeeded with an ID/version-only result, in the mutation's tx.
func (r *receipts) complete(ctx context.Context, tx pgx.Tx, c Ctx, resType, resID string, version int, result map[string]any) error {
	if c.OpID == "" {
		return nil
	}
	if result == nil {
		result = map[string]any{}
	}
	tag, err := tx.Exec(ctx, `UPDATE operation_receipts SET status = 'succeeded', resource_type = $5, resource_id = $6,
		resource_version = $7, result = $8, completed_at = now(), lease_owner = NULL, lease_expires = NULL
		WHERE app = $1 AND subject = $2 AND actor = $3 AND op_id = $4`, c.App, c.Principal.Subject, c.Actor(), c.OpID,
		resType, resID, version, result)
	if err == nil && tag.RowsAffected() != 1 {
		err = errs.Internal("receipt for %s disappeared", c.OpID)
	}
	return err
}

// assign records the resource a pending (long-running) operation is producing.
func (r *receipts) assign(ctx context.Context, tx pgx.Tx, c Ctx, resType, resID string) error {
	if c.OpID == "" {
		return nil
	}
	_, err := tx.Exec(ctx, `UPDATE operation_receipts SET resource_type = $5, resource_id = $6
		WHERE app = $1 AND subject = $2 AND actor = $3 AND op_id = $4`, c.App, c.Principal.Subject, c.Actor(), c.OpID, resType, resID)
	return err
}

// Get returns the caller's own receipt (operation status), for clients that lost a response.
func (r *receipts) Get(ctx context.Context, c Ctx, opID string) (*Receipt, error) {
	if !ValidOpID(opID) {
		return nil, errs.NotFound("operation not found")
	}
	var out *Receipt
	err := r.core.inApp(ctx, c, func(tx pgx.Tx, _ *Access) error {
		rc := &Receipt{OpID: opID}
		var resType, resID *string
		var resVersion *int
		err := tx.QueryRow(ctx, `SELECT op_type, status, resource_type, resource_id, resource_version, result, created_at,
			completed_at FROM operation_receipts WHERE app = $1 AND subject = $2 AND actor = $3 AND op_id = $4`,
			c.App, c.Principal.Subject, c.Actor(), opID).
			Scan(&rc.Type, &rc.Status, &resType, &resID, &resVersion, &rc.Result, &rc.CreatedAt, &rc.CompletedAt)
		if errors.Is(err, pgx.ErrNoRows) {
			return errs.NotFound("operation not found")
		}
		if resType != nil {
			rc.ResourceType = *resType
		}
		if resID != nil {
			rc.ResourceID = *resID
		}
		if resVersion != nil {
			rc.ResourceVersion = *resVersion
		}
		out = rc
		return err
	})
	return out, err
}
