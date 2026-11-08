// Package admin holds privileged operations that the API server cannot perform: provisioning apps
// and their workload clients, moving data between scopes, and changing owners. They run on the
// migration login as strongbox_owner (`strongbox admin ...`), never on the runtime login, and each
// one writes an audit event in the same transaction.
package admin

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/paulmalmquist/storage_relspace/internal/audit"
	"github.com/paulmalmquist/storage_relspace/internal/crypto"
	"github.com/paulmalmquist/storage_relspace/internal/errs"
	"github.com/paulmalmquist/storage_relspace/internal/markings"
	"github.com/paulmalmquist/storage_relspace/internal/service"
	"github.com/paulmalmquist/storage_relspace/internal/store"
)

// Admin runs privileged operations on the owner pool.
type Admin struct {
	Pool    *pgxpool.Pool // migration login (member of strongbox_owner)
	KMS     crypto.KeyProvider
	Actor   string // recorded in audit events, e.g. "admin-cli:alice@example.com"
	Stripes int
}

// tx runs fn as strongbox_owner with the app context set (so audit and key helpers see the app).
func (a *Admin) tx(ctx context.Context, app string, fn func(tx pgx.Tx) error) error {
	return pgx.BeginFunc(ctx, a.Pool, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `SET LOCAL ROLE `+store.OwnerRole); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `SELECT set_config('strongbox.app', $1, true), set_config('strongbox.subject', $2, true),
			set_config('strongbox.actor', $2, true), set_config('strongbox.mode', 'worker', true)`, app, a.Actor); err != nil {
			return err
		}
		return fn(tx)
	})
}

func (a *Admin) audit(ctx context.Context, tx pgx.Tx, app, action, resType, resID, reason string, details map[string]any) error {
	_, err := audit.New(nil, a.Stripes).Append(ctx, tx, audit.Entry{App: app, Anonymous: a.Actor, Action: action,
		ResourceType: resType, ResourceID: resID, Decision: "allow", Reason: reason, Details: details})
	return err
}

// CreateApp provisions an app with its first admin (a registered principal).
func (a *Admin) CreateApp(ctx context.Context, app, displayName, firstAdmin string) error {
	if !store.ValidApp(app) {
		return errs.Invalid("app must look like <app_id>:<env>, e.g. notes:prod")
	}
	return a.tx(ctx, app, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `INSERT INTO apps (app, display_name, created_by) VALUES ($1, $2, $3)`, app, nullable(displayName), a.Actor); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `INSERT INTO app_members (app, subject, role, added_by) VALUES ($1, $2, 'admin', $3)`, app, firstAdmin, a.Actor); err != nil {
			return fmt.Errorf("first admin %s: %w", firstAdmin, err)
		}
		return a.audit(ctx, tx, app, "app.create", "app", app, "app created", map[string]any{"first_admin": firstAdmin})
	})
}

// SetAppStatus suspends or reactivates an app.
func (a *Admin) SetAppStatus(ctx context.Context, app, status string) error {
	if status != "active" && status != "suspended" {
		return errs.Invalid("status must be active or suspended")
	}
	return a.tx(ctx, app, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, `UPDATE apps SET status = $2 WHERE app = $1 AND status <> 'legacy'`, app, status)
		if err == nil && tag.RowsAffected() == 0 {
			err = errs.NotFound("app %s not found", app)
		}
		if err != nil {
			return err
		}
		return a.audit(ctx, tx, app, "app.status", "app", app, "app "+status, nil)
	})
}

// AddClient registers a workload (an app backend, an agent gateway) that may act on behalf of the
// app's members.
func (a *Admin) AddClient(ctx context.Context, app, subject string) error {
	return a.tx(ctx, app, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `INSERT INTO app_clients (app, subject, added_by) VALUES ($1, $2, $3) ON CONFLICT DO NOTHING`,
			app, subject, a.Actor); err != nil {
			return err
		}
		return a.audit(ctx, tx, app, "app.client_add", "app_client", subject, "client registered", nil)
	})
}

func (a *Admin) RemoveClient(ctx context.Context, app, subject string) error {
	return a.tx(ctx, app, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `DELETE FROM app_clients WHERE app = $1 AND subject = $2`, app, subject); err != nil {
			return err
		}
		return a.audit(ctx, tx, app, "app.client_remove", "app_client", subject, "client removed", nil)
	})
}

// SetMember adds or changes a member without an existing admin (recovery, bootstrap).
func (a *Admin) SetMember(ctx context.Context, app, subject, role string) error {
	return a.tx(ctx, app, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `INSERT INTO app_members (app, subject, role, added_by) VALUES ($1, $2, $3, $4)
			ON CONFLICT (app, subject) DO UPDATE SET role = EXCLUDED.role`, app, subject, role, a.Actor); err != nil {
			return err
		}
		return a.audit(ctx, tx, app, "app.member_set", "app_member", subject, "member role set to "+role, nil)
	})
}

// TransferOwner changes a record's or blob's owner. Owner changes are privileged because ownership
// carries manage rights; existing grants keep pointing at the resource.
func (a *Admin) TransferOwner(ctx context.Context, app, kind, id, newOwner string) error {
	table := map[string]string{"record": "records", "blob": "blobs"}[kind]
	if table == "" {
		return errs.Invalid("kind must be record or blob")
	}
	return a.tx(ctx, app, func(tx pgx.Tx) error {
		var member bool
		if err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM app_members WHERE app = $1 AND subject = $2)`, app, newOwner).Scan(&member); err != nil {
			return err
		}
		if !member {
			return errs.Invalid("%s is not a member of %s", newOwner, app)
		}
		var old string
		if err := tx.QueryRow(ctx, `UPDATE `+table+` SET owner = $3 WHERE app = $1 AND id = $2
			RETURNING (SELECT owner FROM `+table+` WHERE app = $1 AND id = $2)`, app, id, newOwner).Scan(&old); err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return errs.NotFound("%s not found", kind)
			}
			return err
		}
		if _, err := tx.Exec(ctx, `UPDATE resource_grants SET resource_owner = $3 WHERE app = $1 AND coalesce(record_id, blob_id) = $2`,
			app, id, newOwner); err != nil {
			return err
		}
		return a.audit(ctx, tx, app, kind+".transfer_owner", kind, id, "owner changed", map[string]any{"from": old, "to": newOwner})
	})
}

// ---- legacy assignment ---------------------------------------------------------------------------

// LegacyReport describes rows in the '_legacy' scope (created before app scoping).
type LegacyReport struct {
	App          string           `json:"app"`
	DryRun       bool             `json:"dry_run"`
	Rows         map[string]int64 `json:"rows"`
	PlaintextCUI int64            `json:"controlled_plaintext_records"`
	Sealed       int64            `json:"sealed"`
	Verified     int64            `json:"verified"`
	Failures     []string         `json:"failures"`
}

var legacyTables = []string{"data_keys", "collections", "records", "record_index", "record_revisions", "blobs"}

// AssignLegacy moves every '_legacy' row to app in one transaction (foreign keys are deferred, so
// keys, collections, records, index rows and blobs move together or not at all). Records that hold
// controlled content in plaintext (written before that was refused) are sealed under the app-bound
// context as part of the move. With verify, every legacy ciphertext is decrypted under its original
// context before commit; any failure rolls the whole move back. dryRun counts and verifies only.
func (a *Admin) AssignLegacy(ctx context.Context, keys *service.Keys, app string, dryRun, verify bool) (LegacyReport, error) {
	rep := LegacyReport{App: app, DryRun: dryRun, Rows: map[string]int64{}, Failures: []string{}}
	errDry := errors.New("dry run")
	err := a.tx(ctx, app, func(tx pgx.Tx) error {
		var status string
		if err := tx.QueryRow(ctx, `SELECT status FROM apps WHERE app = $1`, app).Scan(&status); err != nil || status != "active" {
			return errs.Invalid("target app %s must exist and be active", app)
		}
		for _, t := range legacyTables {
			var n int64
			if err := tx.QueryRow(ctx, `SELECT count(*) FROM `+t+` WHERE app = '_legacy'`).Scan(&n); err != nil {
				return err
			}
			rep.Rows[t] = n
		}
		var clash []string
		rows, err := tx.Query(ctx, `SELECT l.name FROM collections l JOIN collections c ON c.name = l.name AND c.app = $1
			WHERE l.app = '_legacy'`, app)
		if err != nil {
			return err
		}
		if clash, err = pgx.CollectRows(rows, pgx.RowTo[string]); err != nil {
			return err
		}
		if len(clash) > 0 {
			return errs.Conflict("collections already exist in %s: %v", app, clash)
		}
		if err := tx.QueryRow(ctx, `SELECT count(*) FROM records WHERE app = '_legacy' AND data_plain IS NOT NULL
			AND marking <> 'UNCONTROLLED'`).Scan(&rep.PlaintextCUI); err != nil {
			return err
		}
		if verify {
			if err := a.verifyLegacy(ctx, tx, keys, &rep); err != nil {
				return err
			}
			if len(rep.Failures) > 0 {
				return fmt.Errorf("%d legacy objects failed verification; nothing was moved", len(rep.Failures))
			}
		}
		if dryRun {
			return errDry
		}
		if _, err := tx.Exec(ctx, `SET CONSTRAINTS ALL DEFERRED`); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `UPDATE data_keys SET app = $1 WHERE app = '_legacy'`, app); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `UPDATE collections SET app = $1 WHERE app = '_legacy'`, app); err != nil {
			return err
		}
		if err := a.sealPlaintextCUI(ctx, tx, keys, app, &rep); err != nil {
			return err
		}
		for _, t := range []string{"records", "record_index", "record_revisions", "blobs"} {
			if _, err := tx.Exec(ctx, `UPDATE `+t+` SET app = $1 WHERE app = '_legacy'`, app); err != nil {
				return fmt.Errorf("%s: %w", t, err)
			}
		}
		return a.audit(ctx, tx, app, "app.legacy_assign", "app", app, "legacy rows assigned",
			map[string]any{"rows": rep.Rows, "sealed": rep.Sealed, "verified": rep.Verified})
	})
	if errors.Is(err, errDry) {
		err = nil
	}
	return rep, err
}

// sealPlaintextCUI seals controlled plaintext records while moving them to app.
func (a *Admin) sealPlaintextCUI(ctx context.Context, tx pgx.Tx, keys *service.Keys, app string, rep *LegacyReport) error {
	rows, err := tx.Query(ctx, `SELECT id, collection, marking, data_plain, version FROM records
		WHERE app = '_legacy' AND data_plain IS NOT NULL AND marking <> 'UNCONTROLLED'`)
	if err != nil {
		return err
	}
	type row struct {
		id, coll, marking string
		data              map[string]any
		version           int
	}
	list, err := pgx.CollectRows(rows, func(r pgx.CollectableRow) (row, error) {
		var x row
		return x, r.Scan(&x.id, &x.coll, &x.marking, &x.data, &x.version)
	})
	if err != nil {
		return err
	}
	for _, x := range list {
		m, err := markings.Parse(x.marking)
		if err != nil {
			return errs.Integrity("record %s has an invalid marking", x.id)
		}
		aad := []byte(fmt.Sprintf("strongbox/record/v2|%s|%s|%s|%s|%d", app, x.coll, x.id, m.Banner(), x.version))
		keyID, sealed, err := keys.SealJSON(ctx, tx, app, "collection:"+x.coll, aad, x.data)
		if err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `UPDATE records SET app = $2, data_plain = NULL, data_sealed = $3, key_id = $4, aad_version = 2
			WHERE id = $1`, x.id, app, sealed, keyID); err != nil {
			return err
		}
		rep.Sealed++
	}
	return nil
}

// verifyLegacy decrypts each legacy record and blob metadata under its original (pre-app) context.
func (a *Admin) verifyLegacy(ctx context.Context, tx pgx.Tx, keys *service.Keys, rep *LegacyReport) error {
	rows, err := tx.Query(ctx, `SELECT id, collection, marking, data_sealed, key_id, version FROM records
		WHERE app = '_legacy' AND data_sealed IS NOT NULL`)
	if err != nil {
		return err
	}
	type rec struct {
		id, coll, marking, keyID string
		sealed                   []byte
		version                  int
	}
	recs, err := pgx.CollectRows(rows, func(r pgx.CollectableRow) (rec, error) {
		var x rec
		return x, r.Scan(&x.id, &x.coll, &x.marking, &x.sealed, &x.keyID, &x.version)
	})
	if err != nil {
		return err
	}
	for _, x := range recs {
		m, err := markings.Parse(x.marking)
		if err == nil {
			var out json.RawMessage
			aad := []byte(fmt.Sprintf("strongbox/record/v1|%s|%s|%s|%d", x.coll, x.id, m.Banner(), x.version))
			err = keys.OpenJSON(ctx, tx, "_legacy", "collection:"+x.coll, x.keyID, aad, x.sealed, &out)
		}
		if err != nil {
			rep.Failures = append(rep.Failures, "record "+x.id+": "+err.Error())
			continue
		}
		rep.Verified++
	}
	brows, err := tx.Query(ctx, `SELECT id, marking, kek_id, wrapped_dek, meta_key_id, sealed_meta FROM blobs
		WHERE app = '_legacy' AND state = 'active'`)
	if err != nil {
		return err
	}
	type blob struct {
		id, marking, kek, metaKey string
		wrapped, sealed           []byte
	}
	blobs, err := pgx.CollectRows(brows, func(r pgx.CollectableRow) (blob, error) {
		var x blob
		return x, r.Scan(&x.id, &x.marking, &x.kek, &x.wrapped, &x.metaKey, &x.sealed)
	})
	if err != nil {
		return err
	}
	for _, x := range blobs {
		m, err := markings.Parse(x.marking)
		if err == nil {
			_, err = a.KMS.Unwrap(ctx, crypto.WrappedKey{KEKID: x.kek, Ciphertext: x.wrapped},
				[]byte(fmt.Sprintf("strongbox/blob-dek/v2|%s|%s", x.id, m.Banner())))
		}
		if err == nil {
			var out json.RawMessage
			err = keys.OpenJSON(ctx, tx, "_legacy", "blobmeta", x.metaKey, []byte(fmt.Sprintf("strongbox/blob-meta/v2|%s|%s", x.id, m.Banner())), x.sealed, &out)
		}
		if err != nil {
			rep.Failures = append(rep.Failures, "blob "+x.id+": "+err.Error())
			continue
		}
		rep.Verified++
	}
	return nil
}

func nullable(s string) any {
	if s == "" {
		return nil
	}
	return s
}

// ---- quotas and usage ------------------------------------------------------------------------------

// Apps lists every app, the legacy scope included.
func (a *Admin) Apps(ctx context.Context) ([]string, error) {
	var out []string
	err := a.tx(ctx, "_legacy", func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT app FROM apps ORDER BY app`)
		if err != nil {
			return err
		}
		out, err = pgx.CollectRows(rows, pgx.RowTo[string])
		return err
	})
	return out, err
}

// Quota is an app's limits. nil means unlimited.
type Quota struct {
	MaxBlobBytes   *int64 `json:"max_blob_bytes"`
	MaxBlobs       *int64 `json:"max_blobs"`
	MaxRecords     *int64 `json:"max_records"`
	MaxRecordBytes *int64 `json:"max_record_bytes"`
}

// SetQuota replaces an app's limits. Lowering a limit below current usage refuses new growth; it
// never deletes data.
func (a *Admin) SetQuota(ctx context.Context, app string, q Quota) error {
	return a.tx(ctx, app, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `INSERT INTO app_quotas (app, max_blob_bytes, max_blobs, max_records, max_record_bytes, updated_by)
			VALUES ($1,$2,$3,$4,$5,$6) ON CONFLICT (app) DO UPDATE SET max_blob_bytes = EXCLUDED.max_blob_bytes,
			max_blobs = EXCLUDED.max_blobs, max_records = EXCLUDED.max_records, max_record_bytes = EXCLUDED.max_record_bytes,
			updated_by = EXCLUDED.updated_by, updated_at = now()`,
			app, q.MaxBlobBytes, q.MaxBlobs, q.MaxRecords, q.MaxRecordBytes, a.Actor); err != nil {
			return err
		}
		raw, _ := json.Marshal(q)
		var details map[string]any
		_ = json.Unmarshal(raw, &details)
		return a.audit(ctx, tx, app, "app.quota", "app", app, "quota set", details)
	})
}

// Usage is an app's counted usage, and with Recount, what a full scan finds.
type Usage struct {
	App            string `json:"app"`
	Quota          Quota  `json:"quota"`
	BlobBytes      int64  `json:"blob_bytes"`
	Blobs          int64  `json:"blobs"`
	ReservedBytes  int64  `json:"reserved_bytes"`
	Reservations   int64  `json:"reservations"`
	Records        int64  `json:"records"`
	RecordBytes    int64  `json:"record_bytes"`
	Revisions      int64  `json:"revisions"`
	RevisionBytes  int64  `json:"revision_bytes"`
	DeletedRecords int64  `json:"deleted_records"`
	Collections    int64  `json:"collections"`
	Recount        *struct {
		BlobBytes     int64 `json:"blob_bytes"`
		ReservedBytes int64 `json:"reserved_bytes"`
		Reservations  int64 `json:"reservations"`
		Blobs         int64 `json:"blobs"`
		Records       int64 `json:"records"`
		RecordBytes   int64 `json:"record_bytes"`
	} `json:"recount,omitempty"`
	Drift bool `json:"drift"`
}

// AppUsage reads counters (cheap) and, with recount, compares them with a scan (expensive; for
// inventories and drift checks). fix rewrites the counters from the scan.
func (a *Admin) AppUsage(ctx context.Context, app string, recount, fix bool) (*Usage, error) {
	u := &Usage{App: app}
	err := a.tx(ctx, app, func(tx pgx.Tx) error {
		// Writers apply their deltas to these same per-app rows in their transaction.
		// Lock all shards before scanning, including previously empty shards. Other apps
		// keep writing; no application table needs a global SHARE lock.
		if fix {
			if _, err := tx.Exec(ctx, `INSERT INTO blob_usage(app) VALUES($1) ON CONFLICT DO NOTHING`, app); err != nil {
				return err
			}
			if _, err := tx.Exec(ctx, `SELECT app FROM blob_usage WHERE app=$1 FOR UPDATE`, app); err != nil {
				return err
			}
			if _, err := tx.Exec(ctx, `INSERT INTO record_usage(app,shard,records,bytes)
                SELECT $1,shard,0,0 FROM generate_series(0,7) shard ON CONFLICT DO NOTHING`, app); err != nil {
				return err
			}
			if _, err := tx.Exec(ctx, `SELECT shard FROM record_usage WHERE app=$1 ORDER BY shard FOR UPDATE`, app); err != nil {
				return err
			}
		}
		if err := tx.QueryRow(ctx, `SELECT max_blob_bytes, max_blobs, max_records, max_record_bytes FROM app_quotas WHERE app = $1`, app).
			Scan(&u.Quota.MaxBlobBytes, &u.Quota.MaxBlobs, &u.Quota.MaxRecords, &u.Quota.MaxRecordBytes); err != nil && !errors.Is(err, pgx.ErrNoRows) {
			return err
		}
		if err := tx.QueryRow(ctx, `SELECT coalesce(sum(bytes),0), coalesce(sum(blobs),0), coalesce(sum(reserved_bytes),0),
			coalesce(sum(reservations),0) FROM blob_usage WHERE app = $1`, app).Scan(&u.BlobBytes, &u.Blobs, &u.ReservedBytes, &u.Reservations); err != nil {
			return err
		}
		if err := tx.QueryRow(ctx, `SELECT coalesce(sum(records),0), coalesce(sum(bytes),0) FROM record_usage WHERE app = $1`, app).
			Scan(&u.Records, &u.RecordBytes); err != nil {
			return err
		}
		if err := tx.QueryRow(ctx, `SELECT count(*), coalesce(sum(size_bytes),0) FROM record_revisions WHERE app = $1`, app).
			Scan(&u.Revisions, &u.RevisionBytes); err != nil {
			return err
		}
		if err := tx.QueryRow(ctx, `SELECT count(*) FILTER (WHERE deleted_at IS NOT NULL), (SELECT count(*) FROM collections WHERE app = $1)
			FROM records WHERE app = $1`, app).Scan(&u.DeletedRecords, &u.Collections); err != nil {
			return err
		}
		if !recount && !fix {
			return nil
		}
		rc := &struct {
			BlobBytes     int64 `json:"blob_bytes"`
			ReservedBytes int64 `json:"reserved_bytes"`
			Reservations  int64 `json:"reservations"`
			Blobs         int64 `json:"blobs"`
			Records       int64 `json:"records"`
			RecordBytes   int64 `json:"record_bytes"`
		}{}
		if err := tx.QueryRow(ctx, `SELECT coalesce(sum(size_bytes),0), count(*) FROM blobs WHERE app = $1 AND state = 'active'`, app).
			Scan(&rc.BlobBytes, &rc.Blobs); err != nil {
			return err
		}
		if err := tx.QueryRow(ctx, `SELECT count(*), coalesce(sum(sb_record_bytes(records)),0) FROM records WHERE app = $1 AND deleted_at IS NULL`, app).
			Scan(&rc.Records, &rc.RecordBytes); err != nil {
			return err
		}
		if err := tx.QueryRow(ctx, `SELECT coalesce(sum(reserved_bytes),0),count(*) FROM blobs WHERE app=$1 AND state='pending'`, app).Scan(&rc.ReservedBytes, &rc.Reservations); err != nil {
			return err
		}
		u.Recount = rc
		u.Drift = rc.ReservedBytes != u.ReservedBytes || rc.Reservations != u.Reservations || rc.BlobBytes != u.BlobBytes || rc.Blobs != u.Blobs || rc.Records != u.Records || rc.RecordBytes != u.RecordBytes
		if !fix || !u.Drift {
			return nil
		}
		// Rewrite from the scan made while writers were stopped.
		if _, err := tx.Exec(ctx, `WITH actual AS (
            SELECT sb_usage_shard(id) shard,count(*) n,sum(sb_record_bytes(records)) bytes
            FROM records WHERE app=$1 AND deleted_at IS NULL GROUP BY 1)
            UPDATE record_usage u SET records=coalesce(s.n,0),bytes=coalesce(s.bytes,0)
            FROM (SELECT shards.shard,a.n,a.bytes FROM generate_series(0,7) AS shards(shard)
                LEFT JOIN actual a USING(shard)) s WHERE u.app=$1 AND u.shard=s.shard`, app); err != nil {
			return err
		}

		if _, err := tx.Exec(ctx, `UPDATE blob_usage SET bytes = $2, blobs = $3,
			reserved_bytes = (SELECT coalesce(sum(reserved_bytes),0) FROM blobs WHERE app = $1 AND state = 'pending'),
			reservations = (SELECT count(*) FROM blobs WHERE app = $1 AND state = 'pending') WHERE app = $1`,
			app, rc.BlobBytes, rc.Blobs); err != nil {
			return err
		}
		return a.audit(ctx, tx, app, "app.usage_reconcile", "app", app, "usage counters rewritten from a scan", nil)
	})
	return u, err
}
