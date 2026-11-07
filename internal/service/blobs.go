package service

import (
	"bufio"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"io"
	"regexp"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/paulmalmquist/storage_relspace/internal/auth"
	"github.com/paulmalmquist/storage_relspace/internal/crypto"
	"github.com/paulmalmquist/storage_relspace/internal/errs"
	"github.com/paulmalmquist/storage_relspace/internal/markings"
	"github.com/paulmalmquist/storage_relspace/internal/store"
)

// Blob storage: per-object data keys, streaming AES-256-GCM, sealed metadata.
//
// Upload state machine (all transitions are conditional UPDATEs, so exactly one side of any race
// wins):
//
//	pending --commit (lease holder)--> active --delete--> deleted --worker--> purged
//	pending --abort | lease expiry (sweeper)--> aborted --worker--> purged
//	active|deleted --shred--> shredded (wrapped DEK destroyed in the live database)
//
// An uploader holds a lease on its pending row and renews it while streaming. Commit succeeds only
// while the lease is held; the sweeper only aborts rows whose lease has expired. Every attempt
// writes a fresh object key, so a takeover never collides with a stale writer, and the losing side
// deletes its own object (with an outbox job as the durable fallback).

const metaScope = "blob-meta"

var contentTypeRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9!#$&^_.+-]{0,126}/[A-Za-z0-9][A-Za-z0-9!#$&^_.+-]{0,126}(\s*;\s*[A-Za-z0-9_.-]+=[^;\s]{1,64}){0,3}$`)

// blobCtx: version 2 is the pre-app-scoping context, kept readable for legacy blobs.
func blobCtx(aadVersion int, kind, app, id string, m markings.Marking) []byte {
	if aadVersion == 2 {
		return []byte(fmt.Sprintf("strongbox/%s/v2|%s|%s", kind, id, m.Banner()))
	}
	return []byte(fmt.Sprintf("strongbox/%s/v3|%s|%s|%s", kind, app, id, m.Banner()))
}

// objectKey places an attempt's ciphertext under the app's prefix.
func objectKey(app, id, attempt string) string {
	appID, env, _ := strings.Cut(app, ":")
	return "apps/" + appID + "/" + env + "/" + id + "/" + attempt
}

func nonce() string {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

type BlobMeta struct {
	ID          string
	Marking     markings.Marking
	ContentType string
	SizeBytes   *int64
	Filename    string
	Metadata    map[string]any
	State       string
	Owner       string
	Visibility  string
	TeamID      string
	CreatedBy   string
	CreatedAt   time.Time
	Replayed    bool
}

func (b *BlobMeta) JSON() map[string]any {
	md := b.Metadata
	if md == nil {
		md = map[string]any{}
	}
	out := map[string]any{
		"id": b.ID, "marking": b.Marking.Banner(), "content_type": b.ContentType, "size_bytes": b.SizeBytes,
		"filename": optional(b.Filename), "metadata": md, "state": b.State, "owner": b.Owner, "visibility": b.Visibility,
		"team_id": optional(b.TeamID), "created_by": b.CreatedBy, "created_at": b.CreatedAt.UTC().Format(time.RFC3339Nano),
	}
	if b.Replayed {
		out["replayed"] = true
	}
	return out
}

type sealedMeta struct {
	Filename string         `json:"filename,omitempty"`
	Metadata map[string]any `json:"metadata"`
}

type Blobs struct {
	*Core
	keys        *Keys
	receipts    *receipts
	authz       Authorizer
	backend     store.Backend
	kms         crypto.KeyProvider
	ChunkSize   int
	MaxBytes    int64 // largest single-request upload (see Limits)
	MaxBlob     int64 // largest blob, through an upload session
	PartSize    int   // plaintext bytes per session part
	SessionTTL  time.Duration
	MaxMetaSize int
	LeaseTTL    time.Duration
	// DeleteGrace delays object deletion after a logical delete (0: as soon as the worker runs).
	DeleteGrace time.Duration
}

type BlobInput struct {
	Marking      markings.Marking
	ContentType  string
	Filename     string
	Metadata     map[string]any
	DeclaredSize int64 // -1 when unknown
	Visibility   string
	TeamID       string
}

func (b *Blobs) validate(in *BlobInput) error {
	if err := b.validateMeta(in); err != nil {
		return err
	}
	if in.DeclaredSize > b.MaxBytes {
		return errs.PayloadTooLarge("blob exceeds %d bytes; use an upload session (POST /v1/apps/{app}/uploads)", b.MaxBytes)
	}
	return nil
}

func (b *Blobs) validateMeta(in *BlobInput) error {
	if in.ContentType == "" {
		in.ContentType = "application/octet-stream"
	}
	if !contentTypeRe.MatchString(in.ContentType) {
		return errs.Invalid("invalid content type")
	}
	if len(in.Filename) > 255 || strings.ContainsAny(in.Filename, "\x00/\\") {
		return errs.Invalid("filename must be <= 255 characters without path separators")
	}
	if in.Metadata != nil {
		raw, _ := json.Marshal(in.Metadata)
		if len(raw) > b.MaxMeta() {
			return errs.Invalid("metadata exceeds %d bytes", b.MaxMeta())
		}
	}
	return nil
}

func (b *Blobs) MaxMeta() int { return b.MaxMetaSize }

// Upload is an in-progress blob write. Exactly one of Commit or Abort must be called.
type Upload struct {
	svc        *Blobs
	ctx        context.Context
	c          Ctx
	ID         string
	marking    markings.Marking
	enc        *crypto.StreamEncryptor
	writer     store.Writer
	sha        hash.Hash // ciphertext digest, checked on read
	mac        hash.Hash // keyed plaintext digest, stored in the receipt to detect changed retries
	size       int64
	lease      string
	storageKey string
	renewed    time.Time
	open       bool
}

// Replay is a retried upload whose operation already succeeded. The retry's body must match the
// original; Verify reads it and compares keyed digests.
type Replay struct {
	Meta *BlobMeta
	mac  string
	key  []byte
	max  int64
}

// Verify consumes the retried body and confirms it is the content that was stored.
func (r *Replay) Verify(body io.Reader) error {
	m := hmac.New(sha256.New, r.key)
	n, err := io.Copy(m, io.LimitReader(body, r.max+1))
	if err != nil {
		return err
	}
	if n > r.max || r.mac == "" || !hmac.Equal([]byte(hex.EncodeToString(m.Sum(nil))), []byte(r.mac)) {
		return errs.Coded(409, "idempotency_key_reused", "this Idempotency-Key was used to upload different content")
	}
	return nil
}

// Begin authorizes and opens an upload. A retried operation that already succeeded returns a Replay
// instead of an Upload.
func (b *Blobs) Begin(ctx context.Context, c Ctx, in BlobInput) (*Upload, *Replay, error) {
	if err := b.validate(&in); err != nil {
		return nil, nil, err
	}
	u := &Upload{svc: b, ctx: ctx, c: c, marking: in.Marking, sha: sha256.New(), lease: nonce(), open: true}
	var replay *Replay
	var dek []byte
	err := b.inApp(ctx, c, func(tx pgx.Tx, a *Access) error {
		if !a.AtLeast("member") {
			return b.deny(c, auth.BlobCreate, "blob", "", &in.Marking, "app role viewer", errs.Forbidden("viewers cannot upload"))
		}
		vis, team, err := sharing(a, in.Visibility, in.TeamID)
		if err != nil {
			return err
		}
		if _, err := b.check(ctx, tx, c, auth.BlobCreate, "blob", "", &in.Marking, checkOpts{noConceal: true, skipAllow: true}); err != nil {
			return err
		}
		macKeyID, macKey, err := b.keys.Active(ctx, tx, c.App, "receipts", PurposeReceipt)
		if err != nil {
			return err
		}
		_ = macKeyID
		rc, err := b.receipts.claim(ctx, tx, c, Operation{Type: "blob.create", Marking: in.Marking.Banner(),
			Payload: map[string]any{"content_type": in.ContentType, "filename": in.Filename, "metadata": in.Metadata,
				"declared_size": in.DeclaredSize, "visibility": vis, "team_id": team}}, b.LeaseTTL, u.lease)
		if err != nil {
			return err
		}
		if rc != nil && rc.Status == "succeeded" {
			meta, err := b.metaTx(ctx, tx, c, rc.ResourceID, false)
			if err != nil {
				return err
			}
			meta.Replayed = true
			mac, _ := rc.Result["content_mac"].(string)
			replay = &Replay{Meta: meta, mac: mac, key: macKey, max: b.MaxBytes}
			return nil
		}
		if rc != nil && rc.Status == "taken_over" && rc.ResourceID != "" {
			// The previous attempt's lease expired: retire its pending row before starting over.
			if err := b.abortPending(ctx, tx, c.App, rc.ResourceID, ""); err != nil {
				return err
			}
		}
		u.ID = store.NewID("blb")
		u.storageKey = objectKey(c.App, u.ID, u.lease)
		u.mac = hmac.New(sha256.New, macKey)
		dek = crypto.NewDataKey()
		wrapped, err := b.kms.Wrap(ctx, dek, blobCtx(3, "blob-dek", c.App, u.ID, in.Marking))
		if err != nil {
			return kmsError(err)
		}
		metaKey, sealed, err := b.keys.SealJSON(ctx, tx, c.App, metaScope, blobCtx(3, "blob-meta", c.App, u.ID, in.Marking),
			sealedMeta{Filename: in.Filename, Metadata: in.Metadata})
		if err != nil {
			return err
		}
		// The quota trigger reserves the declared size (or the single-request maximum when the size
		// is unknown) until the upload commits or aborts.
		reserve := in.DeclaredSize
		if reserve < 0 {
			reserve = b.MaxBytes
		}
		if _, err := tx.Exec(ctx, `INSERT INTO blobs (app, id, state, marking, content_type, chunk_size, kek_id, wrapped_dek,
			meta_key_id, sealed_meta, storage_key, created_by, owner, visibility, team_id, aad_version, lease_owner, lease_expires,
			reserved_bytes)
			VALUES ($1,$2,'pending',$3,$4,$5,$6,$7,$8,$9,$10,$11,$11,$12,$13,3,$14,$15,$16)`,
			c.App, u.ID, in.Marking.Banner(), in.ContentType, b.ChunkSize, wrapped.KEKID, wrapped.Ciphertext, metaKey, sealed,
			u.storageKey, c.Principal.Subject, vis, team, u.lease, time.Now().Add(b.LeaseTTL), reserve); err != nil {
			return err
		}
		return b.receipts.assign(ctx, tx, c, "blob", u.ID)
	})
	if err != nil || replay != nil {
		return nil, replay, err
	}
	u.renewed = time.Now()
	writer, err := b.backend.OpenWriter(ctx, u.storageKey)
	if err != nil {
		u.writer = nopWriter{}
		u.Abort("object store unavailable")
		return nil, nil, err
	}
	u.writer = writer
	enc, err := crypto.NewStreamEncryptor(dek, blobCtx(3, "blob", c.App, u.ID, in.Marking), b.ChunkSize)
	if err != nil {
		u.Abort("encryptor failed")
		return nil, nil, err
	}
	u.enc = enc
	if err := u.emit(enc.Header()); err != nil {
		u.Abort("write failed")
		return nil, nil, err
	}
	return u, nil, nil
}

type nopWriter struct{}

func (nopWriter) Write(p []byte) (int, error) { return len(p), nil }
func (nopWriter) Commit() error               { return nil }
func (nopWriter) Abort() error                { return nil }

func (u *Upload) emit(ct []byte) error {
	if len(ct) == 0 {
		return nil
	}
	u.sha.Write(ct)
	_, err := u.writer.Write(ct)
	return err
}

// renew extends the lease while streaming; losing it (swept) stops the upload.
func (u *Upload) renew() error {
	if time.Since(u.renewed) < u.svc.LeaseTTL/3 {
		return nil
	}
	err := u.svc.DB.Run(u.ctx, u.c.scope(), func(tx pgx.Tx) error {
		tag, err := tx.Exec(u.ctx, `UPDATE blobs SET lease_expires = $4 WHERE app = $1 AND id = $2 AND state = 'pending'
			AND lease_owner = $3`, u.c.App, u.ID, u.lease, time.Now().Add(u.svc.LeaseTTL))
		if err != nil {
			return err
		}
		if tag.RowsAffected() != 1 {
			return errs.Conflict("upload lease lost (expired or aborted)")
		}
		if u.c.OpID != "" {
			_, err = tx.Exec(u.ctx, `UPDATE operation_receipts SET lease_expires = $5 WHERE app = $1 AND subject = $2
				AND actor = $3 AND op_id = $4 AND status = 'pending'`, u.c.App, u.c.Principal.Subject, u.c.Actor(), u.c.OpID,
				time.Now().Add(u.svc.LeaseTTL))
		}
		return err
	})
	if err == nil {
		u.renewed = time.Now()
	}
	return err
}

// Write accepts plaintext.
func (u *Upload) Write(p []byte) (int, error) {
	if !u.open {
		return 0, errors.New("upload is closed")
	}
	u.size += int64(len(p))
	if u.size > u.svc.MaxBytes {
		u.Abort("size limit exceeded")
		return 0, errs.PayloadTooLarge("blob exceeds %d bytes; use an upload session (POST /v1/apps/{app}/uploads)", u.svc.MaxBytes)
	}
	u.mac.Write(p)
	ct, err := u.enc.Update(p)
	if err == nil {
		err = u.emit(ct)
	}
	if err == nil {
		err = u.renew()
	}
	if err != nil {
		u.Abort("write failed: " + err.Error())
		return 0, err
	}
	return len(p), nil
}

// Commit finishes the object and activates the row, only if this upload still holds its lease.
func (u *Upload) Commit() (*BlobMeta, error) {
	if !u.open {
		return nil, errors.New("upload is closed")
	}
	tail, err := u.enc.Finalize()
	if err == nil {
		err = u.emit(tail)
	}
	if err == nil {
		err = u.writer.Commit()
	}
	if err != nil {
		u.Abort("commit failed")
		return nil, err
	}
	u.open = false
	// The body is fully received: finishing must not depend on the client staying connected.
	ctx, cancel := context.WithTimeout(context.WithoutCancel(u.ctx), 30*time.Second)
	defer cancel()
	var meta *BlobMeta
	err = u.svc.inApp(ctx, u.c, func(tx pgx.Tx, _ *Access) error {
		tag, err := tx.Exec(ctx, `UPDATE blobs SET state = 'active', size_bytes = $4, ciphertext_sha256 = $5,
			lease_owner = NULL, lease_expires = NULL WHERE app = $1 AND id = $2 AND state = 'pending' AND lease_owner = $3`,
			u.c.App, u.ID, u.lease, u.size, hex.EncodeToString(u.sha.Sum(nil)))
		if err != nil {
			return err
		}
		if tag.RowsAffected() != 1 {
			return errs.Coded(409, "upload_expired", "the upload's lease expired before it completed; upload again")
		}
		if err := u.svc.receipts.complete(ctx, tx, u.c, "blob", u.ID, 1,
			map[string]any{"content_mac": hex.EncodeToString(u.mac.Sum(nil))}); err != nil {
			return err
		}
		if err := u.svc.note(ctx, tx, u.c, auth.BlobCreate, "blob", u.ID, "allow", "blob stored", &u.marking,
			map[string]any{"size_bytes": u.size}); err != nil {
			return err
		}
		meta, err = u.svc.metaTx(ctx, tx, u.c, u.ID, false)
		return err
	})
	if err != nil {
		// This attempt lost (or could not finish): remove its object now, and durably via the outbox.
		_ = u.svc.backend.Delete(ctx, u.storageKey)
		_ = u.svc.DB.Run(ctx, u.c.scope(), func(tx pgx.Tx) error { return u.svc.abortPending(ctx, tx, u.c.App, u.ID, u.lease) })
		return nil, err
	}
	return meta, nil
}

// Abort discards the upload. Safe to call more than once.
func (u *Upload) Abort(reason string) {
	if !u.open {
		return
	}
	u.open = false
	ctx, cancel := context.WithTimeout(context.WithoutCancel(u.ctx), 10*time.Second)
	defer cancel()
	_ = u.writer.Abort()
	if u.ID == "" {
		return
	}
	_ = u.svc.DB.Run(ctx, u.c.scope(), func(tx pgx.Tx) error {
		if err := u.svc.abortPending(ctx, tx, u.c.App, u.ID, u.lease); err != nil {
			return err
		}
		if u.c.OpID != "" { // let a retry with the same key start immediately
			if _, err := tx.Exec(ctx, `UPDATE operation_receipts SET lease_expires = now() WHERE app = $1 AND subject = $2
				AND actor = $3 AND op_id = $4 AND status = 'pending'`, u.c.App, u.c.Principal.Subject, u.c.Actor(), u.c.OpID); err != nil {
				return err
			}
		}
		return u.svc.note(ctx, tx, u.c, auth.BlobCreate, "blob", u.ID, "error", "upload aborted: "+reason, &u.marking, nil)
	})
}

// abortPending moves a pending row to aborted (only if leaseOwner still holds it, when given) and
// enqueues deletion of its object.
func (b *Blobs) abortPending(ctx context.Context, tx pgx.Tx, app, id, leaseOwner string) error {
	q := `UPDATE blobs SET state = 'aborted', lease_owner = NULL, lease_expires = NULL
		WHERE app = $1 AND id = $2 AND state = 'pending'`
	args := []any{app, id}
	if leaseOwner != "" {
		q += ` AND lease_owner = $3`
		args = append(args, leaseOwner)
	}
	var key, layout string
	err := tx.QueryRow(ctx, q+` RETURNING storage_key, layout`, args...).Scan(&key, &layout)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil
	}
	if err != nil {
		return err
	}
	keys, err := objectKeys(ctx, tx, app, id, key, layout)
	if err != nil {
		return err
	}
	return enqueueObjectDelete(ctx, tx, app, id, keys, 0)
}

// Put stores a small in-memory object.
func (b *Blobs) Put(ctx context.Context, c Ctx, data []byte, in BlobInput) (*BlobMeta, error) {
	in.DeclaredSize = int64(len(data))
	u, replay, err := b.Begin(ctx, c, in)
	if err != nil {
		return nil, err
	}
	if replay != nil {
		if err := replay.Verify(strings.NewReader(string(data))); err != nil {
			return nil, err
		}
		return replay.Meta, nil
	}
	if _, err := u.Write(data); err != nil {
		return nil, err
	}
	return u.Commit()
}

// ---- reads ---------------------------------------------------------------------------------------

type blobRow struct {
	id, state, marking, contentType, kekID, metaKeyID, storageKey, createdBy, owner, visibility, layout string
	teamID                                                                                              *string
	size, declaredSize                                                                                  *int64
	partSize                                                                                            *int
	chunkSize                                                                                           int
	wrappedDEK, sealedMeta                                                                              []byte
	sha                                                                                                 *string
	aadVersion                                                                                          int
	createdAt                                                                                           time.Time
	leaseExpires                                                                                        *time.Time
}

const blobCols = `id, state, marking, content_type, size_bytes, kek_id, wrapped_dek, meta_key_id, sealed_meta,
	ciphertext_sha256, storage_key, created_by, created_at, owner, visibility, team_id, aad_version, layout,
	part_size, declared_size, chunk_size, lease_expires`

func scanBlob(row pgx.Row) (*blobRow, error) {
	var r blobRow
	err := row.Scan(&r.id, &r.state, &r.marking, &r.contentType, &r.size, &r.kekID, &r.wrappedDEK, &r.metaKeyID,
		&r.sealedMeta, &r.sha, &r.storageKey, &r.createdBy, &r.createdAt, &r.owner, &r.visibility, &r.teamID, &r.aadVersion,
		&r.layout, &r.partSize, &r.declaredSize, &r.chunkSize, &r.leaseExpires)
	return &r, err
}

func (r *blobRow) resource() Resource {
	res := Resource{Kind: "blob", ID: r.id, Owner: r.owner, Visibility: r.visibility}
	if r.teamID != nil {
		res.TeamID = *r.teamID
	}
	return res
}

func (b *Blobs) row(ctx context.Context, tx pgx.Tx, app, id string) (*blobRow, markings.Marking, error) {
	r, err := scanBlob(tx.QueryRow(ctx, `SELECT `+blobCols+` FROM blobs WHERE app = $1 AND id = $2 AND state = 'active'`, app, id))
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, markings.Marking{}, errs.NotFound("blob not found")
	}
	if err != nil {
		return nil, markings.Marking{}, err
	}
	m, err := markings.Parse(r.marking)
	if err != nil {
		return nil, m, errs.Integrity("stored marking is invalid")
	}
	return r, m, nil
}

func (b *Blobs) meta(ctx context.Context, tx pgx.Tx, app string, r *blobRow, m markings.Marking) (*BlobMeta, error) {
	var sm sealedMeta
	if err := b.keys.OpenJSON(ctx, tx, app, b.metaScopeFor(r), r.metaKeyID, blobCtx(r.aadVersion, "blob-meta", app, r.id, m), r.sealedMeta, &sm); err != nil {
		return nil, err
	}
	out := &BlobMeta{ID: r.id, Marking: m, ContentType: r.contentType, SizeBytes: r.size, Filename: sm.Filename,
		Metadata: sm.Metadata, State: r.state, Owner: r.owner, Visibility: r.visibility, CreatedBy: r.createdBy, CreatedAt: r.createdAt}
	if r.teamID != nil {
		out.TeamID = *r.teamID
	}
	return out, nil
}

// metaScopeFor keeps legacy blobs (pre-app-scoping key scope "blobmeta") readable.
func (b *Blobs) metaScopeFor(r *blobRow) string {
	if r.aadVersion == 2 {
		return "blobmeta"
	}
	return metaScope
}

// metaTx reads metadata in an open transaction. audit records the read as an allow event.
func (b *Blobs) metaTx(ctx context.Context, tx pgx.Tx, c Ctx, id string, audit bool) (*BlobMeta, error) {
	r, m, err := b.row(ctx, tx, c.App, id)
	if err != nil {
		return nil, err
	}
	if _, err := b.check(ctx, tx, c, auth.BlobReadMeta, "blob", id, &m, checkOpts{skipAllow: !audit}); err != nil {
		return nil, err
	}
	return b.meta(ctx, tx, c.App, r, m)
}

func (b *Blobs) Meta(ctx context.Context, c Ctx, id string) (*BlobMeta, error) {
	var out *BlobMeta
	err := b.inApp(ctx, c, func(tx pgx.Tx, _ *Access) error {
		m, err := b.metaTx(ctx, tx, c, id, true)
		out = m
		return err
	})
	return out, err
}

type contentReader struct {
	io.Reader
	src      io.Closer
	sha      hash.Hash
	expected string
	onError  func(error)
	failed   bool
}

func (r *contentReader) Read(p []byte) (int, error) {
	n, err := r.Reader.Read(p)
	if errors.Is(err, io.EOF) && r.expected != "" && hex.EncodeToString(r.sha.Sum(nil)) != r.expected {
		err = errs.Integrity("stored ciphertext digest mismatch")
	}
	if err != nil && !errors.Is(err, io.EOF) && errs.Is(err, "integrity_violation") && !r.failed {
		r.failed = true
		r.onError(err)
	}
	return n, err
}

func (r *contentReader) Close() error { return r.src.Close() }

// Open authorizes and returns metadata plus a plaintext reader. Authorization and its audit event
// commit before streaming starts; the first segment is decrypted before returning, so a missing
// object, a wrong key or tampering at the start fails before a response begins. Revocation applies
// to the next Open: a stream already authorized runs to completion (bounded by the request deadline).
func (b *Blobs) Open(ctx context.Context, c Ctx, id string) (*BlobMeta, io.ReadCloser, error) {
	var row *blobRow
	var m markings.Marking
	var meta *BlobMeta
	err := b.inApp(ctx, c, func(tx pgx.Tx, _ *Access) error {
		var err error
		if row, m, err = b.row(ctx, tx, c.App, id); err != nil {
			return err
		}
		if _, err := b.check(ctx, tx, c, auth.BlobReadContent, "blob", id, &m, checkOpts{needContent: true}); err != nil {
			return err
		}
		meta, err = b.meta(ctx, tx, c.App, row, m)
		return err
	})
	if err != nil {
		return nil, nil, err
	}
	audited := func(err error) {
		b.noteAfter(ctx, c, auth.BlobReadContent, "blob", id, "error", "integrity failure: "+err.Error(), &m)
	}
	dek, err := b.kms.Unwrap(ctx, crypto.WrappedKey{KEKID: row.kekID, Ciphertext: row.wrappedDEK}, blobCtx(row.aadVersion, "blob-dek", c.App, id, m))
	if err != nil {
		if errs.Is(err, "integrity_violation") {
			audited(err)
			return nil, nil, err
		}
		return nil, nil, kmsError(err)
	}
	var src io.ReadCloser
	sha := sha256.New()
	expected := ""
	if row.layout == "parts" {
		// Each part's digest is checked as it ends; the row's digest covers the list of parts.
		pr, err := b.openParts(ctx, c, row)
		if err != nil {
			if errs.Is(err, "integrity_violation") {
				audited(err)
			}
			return nil, nil, err
		}
		src = pr
	} else {
		if src, err = b.backend.Read(ctx, row.storageKey); err != nil {
			return nil, nil, err
		}
		if row.sha != nil {
			expected = *row.sha
		}
	}
	dec, err := crypto.NewDecryptingReader(io.TeeReader(src, sha), dek, blobCtx(row.aadVersion, "blob", c.App, id, m))
	if err != nil {
		_ = src.Close()
		return nil, nil, err
	}
	cr := &contentReader{Reader: dec, src: src, sha: sha, expected: expected, onError: audited}
	buffered := bufio.NewReaderSize(cr, 256*1024)
	if _, err := buffered.Peek(1); err != nil && !errors.Is(err, io.EOF) {
		_ = src.Close()
		return nil, nil, err
	}
	return meta, struct {
		io.Reader
		io.Closer
	}{buffered, cr}, nil
}

// ReadAll is Open plus io.ReadAll, for small objects.
func (b *Blobs) ReadAll(ctx context.Context, c Ctx, id string) (*BlobMeta, []byte, error) {
	meta, rc, err := b.Open(ctx, c, id)
	if err != nil {
		return nil, nil, err
	}
	defer rc.Close()
	data, err := io.ReadAll(rc)
	return meta, data, err
}

// List returns active blobs visible to the caller, newest first. Blobs whose metadata the caller
// may not see are excluded in SQL before LIMIT.
func (b *Blobs) List(ctx context.Context, c Ctx, limit int, cur string) ([]*BlobMeta, string, error) {
	n, err := ClampLimit(limit, 50)
	if err != nil {
		return nil, "", err
	}
	var out []*BlobMeta
	var next string
	err = b.inApp(ctx, c, func(tx pgx.Tx, _ *Access) error {
		if _, err := b.check(ctx, tx, c, auth.BlobList, "blob", "", nil, checkOpts{skipAllow: true}); err != nil {
			return err
		}
		rows, err := tx.Query(ctx, `SELECT marking FROM marking_catalog WHERE app = $1 AND scope = 'blobs'`, c.App)
		if err != nil {
			return err
		}
		present, err := pgx.CollectRows(rows, pgx.RowTo[string])
		if err != nil {
			return err
		}
		allowed := []string{}
		for _, banner := range present {
			if m, err := markings.Parse(banner); err == nil && b.Policy.Evaluate(c.Principal, auth.BlobReadMeta, &m).Allowed {
				allowed = append(allowed, banner)
			}
		}
		q := `SELECT ` + blobCols + ` FROM blobs WHERE app = $1 AND state = 'active' AND marking = ANY($2)`
		args := []any{c.App, allowed}
		if cur != "" {
			t, id, err := DecodeCursor(cur, c.App, "blobs")
			if err != nil {
				return err
			}
			args = append(args, t, id)
			q += ` AND (created_at, id) < ($3, $4)`
		}
		rows, err = tx.Query(ctx, q+fmt.Sprintf(` ORDER BY created_at DESC, id DESC LIMIT %d`, n+1), args...)
		if err != nil {
			return err
		}
		all, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (*blobRow, error) { return scanBlob(row) })
		if err != nil {
			return err
		}
		if len(all) > n {
			all = all[:n]
			last := all[n-1]
			next = EncodeCursor(c.App, "blobs", last.createdAt, last.id)
		}
		for _, r := range all {
			m, _ := markings.Parse(r.marking)
			meta, err := b.meta(ctx, tx, c.App, r, m)
			if err != nil {
				return err
			}
			out = append(out, meta)
		}
		return b.note(ctx, tx, c, auth.BlobList, "blob", "", "allow", "listed blobs", nil, map[string]any{"returned": len(out)})
	})
	return out, next, err
}

// Delete removes a blob logically now and its object through the outbox. shred also destroys the
// wrapped data key in the live database. Database backups still hold the wrapped key and object
// versions may persist until their own expiry (docs/RETENTION.md).
func (b *Blobs) Delete(ctx context.Context, c Ctx, id string, shred bool) error {
	return b.inApp(ctx, c, func(tx pgx.Tx, a *Access) error {
		r, m, err := b.row(ctx, tx, c.App, id)
		if err != nil {
			return err
		}
		action := auth.BlobDelete
		if shred {
			action = auth.BlobShred
		}
		if _, err := b.check(ctx, tx, c, auth.BlobReadMeta, "blob", id, &m, checkOpts{skipAllow: true}); err != nil {
			return err
		}
		perm, why, err := b.authz.Permissions(ctx, tx, a, r.resource())
		if err != nil {
			return err
		}
		if !perm.Has(PermManage) {
			return b.deny(c, action, "blob", id, &m, "sharing: "+strings.Join(why, ","), errs.Forbidden("you may not delete this blob"))
		}
		if _, err := b.check(ctx, tx, c, action, "blob", id, &m, checkOpts{noConceal: true, skipAllow: true}); err != nil {
			return err
		}
		tag, err := tx.Exec(ctx, `UPDATE blobs SET state = CASE WHEN $3 THEN 'shredded' ELSE 'deleted' END,
			wrapped_dek = CASE WHEN $3 THEN NULL ELSE wrapped_dek END, deleted_at = now(),
			shredded_at = CASE WHEN $3 THEN now() ELSE NULL END
			WHERE app = $1 AND id = $2 AND state = 'active'`, c.App, id, shred)
		if err != nil {
			return err
		}
		if tag.RowsAffected() != 1 {
			return errs.NotFound("blob not found")
		}
		keys, err := objectKeys(ctx, tx, c.App, id, r.storageKey, r.layout)
		if err != nil {
			return err
		}
		if err := enqueueObjectDelete(ctx, tx, c.App, id, keys, b.DeleteGrace); err != nil {
			return err
		}
		reason := "blob deleted; object deletion queued"
		if shred {
			reason = "blob shredded: wrapped data key destroyed; object deletion queued"
		}
		return b.note(ctx, tx, c, action, "blob", id, "allow", reason, &m, nil)
	})
}
