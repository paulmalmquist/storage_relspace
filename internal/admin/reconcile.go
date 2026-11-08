package admin

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"time"

	"cloud.google.com/go/storage"
	"github.com/jackc/pgx/v5"

	"github.com/paulmalmquist/storage_relspace/internal/crypto"
	"github.com/paulmalmquist/storage_relspace/internal/errs"
	"github.com/paulmalmquist/storage_relspace/internal/store"
)

type ReconcileOptions struct {
	Apply         bool
	FixCounters   bool
	Limit         int
	Cursor        string
	MinAge        time.Duration
	ObjectTimeout time.Duration
}
type ObjectFinding struct {
	Key  string `json:"key"`
	Kind string `json:"kind"`
}
type ReconcileReport struct {
	App               string          `json:"app"`
	DryRun            bool            `json:"dry_run"`
	CheckedReferences int             `json:"checked_references"`
	CheckedObjects    int             `json:"checked_objects"`
	Missing           int             `json:"missing"`
	SizeMismatch      int             `json:"size_mismatch"`
	Orphans           int             `json:"orphans"`
	Queued            int             `json:"queued"`
	Protected         int             `json:"protected"`
	Findings          []ObjectFinding `json:"findings"`
	Next              string          `json:"next_cursor,omitempty"`
	Usage             *Usage          `json:"usage,omitempty"`
	CountersFixed     bool            `json:"counters_fixed"`
	ExpiredUploads    int64           `json:"expired_uploads"`
	DeadJobs          int64           `json:"dead_jobs"`
	ExpiredJobLeases  int64           `json:"expired_job_leases"`
}

func (r *ReconcileReport) add(key, kind string) {
	if len(r.Findings) < store.InventoryPageSize {
		r.Findings = append(r.Findings, ObjectFinding{Key: key, Kind: kind})
	}
}

type reconcileCursor struct{ App, Phase, After string }

func (c reconcileCursor) encode() string {
	raw, _ := json.Marshal(c)
	return base64.RawURLEncoding.EncodeToString(raw)
}
func missingObject(err error) bool {
	return errors.Is(err, os.ErrNotExist) || errors.Is(err, storage.ErrObjectNotExist) || errs.Is(err, "not_found")
}

// Reconcile scans one bounded page under the operator identity. It never deletes an object
// directly. Apply queues a generation-specific job and its audit event in one SQL transaction.
func (a *Admin) Reconcile(ctx context.Context, backend store.Backend, app string, o ReconcileOptions) (*ReconcileReport, error) {
	prefix, err := store.AppObjectPrefix(app)
	if err != nil {
		return nil, err
	}
	inventory, ok := backend.(store.Inventory)
	if !ok {
		return nil, store.ErrInventoryUnsupported
	}
	if o.Limit == 0 {
		o.Limit = store.InventoryPageSize
	}
	if o.Limit < 1 || o.Limit > store.InventoryPageSize {
		return nil, errors.New("limit must be 1-200")
	}
	if o.MinAge == 0 {
		o.MinAge = store.OrphanGrace
	}
	if o.MinAge < store.OrphanGrace {
		return nil, errors.New("orphan grace must be at least 24 hours")
	}
	if o.ObjectTimeout == 0 {
		o.ObjectTimeout = 30 * time.Second
	}
	if o.ObjectTimeout < 0 {
		return nil, errors.New("object timeout must be positive")
	}
	if o.FixCounters && o.Cursor != "" {
		return nil, errors.New("fix-counters is only available on the first scan page")
	}
	if o.FixCounters && !o.Apply {
		return nil, errors.New("fix-counters requires apply")
	}
	c := reconcileCursor{App: app, Phase: "references"}
	if o.Cursor != "" {
		raw, e := base64.RawURLEncoding.DecodeString(o.Cursor)
		if e != nil || len(raw) > 4096 {
			return nil, errors.New("invalid reconciliation cursor")
		}
		if json.Unmarshal(raw, &c) != nil || c.App != app || c.Phase != "references" && c.Phase != "objects" || c.After != "" && !store.ValidStorageKey(c.After) {
			return nil, errors.New("cursor belongs to another app or scan")
		}
	}
	rep := &ReconcileReport{App: app, DryRun: !o.Apply, Findings: []ObjectFinding{}}
	// Refuse absent apps: a restore writes its objects before making the app visible at COMMIT.
	if err := a.tx(ctx, app, func(tx pgx.Tx) error {
		var exists bool
		if err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM apps WHERE app=$1)`, app).Scan(&exists); err != nil {
			return err
		}
		if !exists {
			return errors.New("app must exist before reconciliation")
		}
		return tx.QueryRow(ctx, `SELECT
   (SELECT count(*) FROM blobs WHERE app=$1 AND state='pending' AND lease_expires<now()),
   (SELECT count(*) FROM outbox WHERE app=$1 AND status='dead'),
   (SELECT count(*) FROM outbox WHERE app=$1 AND status='leased' AND lease_expires<now())`, app).Scan(&rep.ExpiredUploads, &rep.DeadJobs, &rep.ExpiredJobLeases)
	}); err != nil {
		return nil, err
	}
	if o.Cursor == "" {
		rep.Usage, err = a.AppUsage(ctx, app, true, o.FixCounters)
		if err != nil {
			return nil, err
		}
		rep.CountersFixed = o.FixCounters && rep.Usage.Drift
	}
	remaining := o.Limit
	if c.Phase == "references" {
		type reference struct {
			key  string
			size int64
		}
		var refs []reference
		err = a.tx(ctx, app, func(tx pgx.Tx) error {
			rows, err := tx.Query(ctx, `SELECT storage_key,cipher_bytes FROM (
     SELECT storage_key,size_bytes + $4::bigint + $5::bigint*greatest(1,(size_bytes+chunk_size-1)/chunk_size) AS cipher_bytes
       FROM blobs WHERE app=$1 AND state='active' AND layout='single'
     UNION ALL SELECT p.storage_key,p.cipher_bytes FROM blob_parts p JOIN blobs b ON b.app=p.app AND b.id=p.blob_id
       WHERE p.app=$1 AND b.state IN ('active','pending')) required
     WHERE storage_key>$2 ORDER BY storage_key LIMIT $3`, app, c.After, remaining+1, crypto.HeaderBytes, crypto.ChunkOverhead)
			if err != nil {
				return err
			}
			refs, err = pgx.CollectRows(rows, func(r pgx.CollectableRow) (reference, error) { var v reference; return v, r.Scan(&v.key, &v.size) })
			return err
		})
		if err != nil {
			return nil, err
		}
		more := len(refs) > remaining
		if more {
			refs = refs[:remaining]
		}
		for _, ref := range refs {
			call, cancel := context.WithTimeout(ctx, o.ObjectTimeout)
			info, e := inventory.StatObject(call, ref.key)
			cancel()
			rep.CheckedReferences++
			remaining--
			switch {
			case missingObject(e):
				rep.Missing++
				rep.add(ref.key, "missing")
			case e != nil:
				return rep, e
			case ref.size >= 0 && info.Size != ref.size:
				rep.SizeMismatch++
				rep.add(ref.key, "size_mismatch")
			}
			c.After = ref.key
		}
		if more {
			rep.Next = c.encode()
			return rep, nil
		}
		c.Phase, c.After = "objects", ""
	}
	if remaining == 0 {
		rep.Next = c.encode()
		return rep, nil
	}
	call, cancel := context.WithTimeout(ctx, o.ObjectTimeout)
	objects, next, err := inventory.ListObjects(call, prefix, c.After, remaining)
	cancel()
	if err != nil {
		return rep, err
	}
	for _, object := range objects {
		rep.CheckedObjects++
		if !strings.HasPrefix(object.Key, prefix) || !store.ValidStorageKey(object.Key) {
			return rep, errors.New("backend inventory escaped app scope")
		}
		if object.Version == "" || object.Updated.IsZero() {
			return rep, errors.New("backend supplied no stable generation or modification time")
		}
		if object.Updated.After(time.Now().Add(-o.MinAge)) {
			rep.Protected++
			continue
		}
		err = a.tx(ctx, app, func(tx pgx.Tx) error {
			referenced, err := store.ObjectReferenced(ctx, tx, app, object.Key)
			if err != nil {
				return err
			}
			if referenced {
				rep.Protected++
				return nil
			}
			rep.Orphans++
			rep.add(object.Key, "orphan")
			if !o.Apply {
				return nil
			}
			raw, err := json.Marshal(object)
			if err != nil {
				return err
			}
			tag, err := tx.Exec(ctx, `INSERT INTO outbox(app,kind,payload) VALUES($1,'object.orphan_delete',$2) ON CONFLICT DO NOTHING`, app, raw)
			if err != nil {
				return err
			}
			if tag.RowsAffected() == 0 {
				return nil
			}
			if err := a.audit(ctx, tx, app, "object.reconcile", "object", object.Key, "unreferenced generation queued for conditional cleanup", map[string]any{"version": object.Version}); err != nil {
				return err
			}
			rep.Queued++
			return nil
		})
		if err != nil {
			return rep, err
		}
	}
	if next != "" {
		c.After = next
		rep.Next = c.encode()
	}
	return rep, nil
}
