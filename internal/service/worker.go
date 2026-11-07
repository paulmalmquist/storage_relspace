package service

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/paulmalmquist/storage_relspace/internal/audit"
	"github.com/paulmalmquist/storage_relspace/internal/store"
	"github.com/paulmalmquist/storage_relspace/internal/telemetry"
)

// The worker is Strongbox's single background mechanism. Each pass:
//
//  1. dispatches outbox jobs (object deletion): claimed with FOR UPDATE SKIP LOCKED under a lease,
//     executed, then marked done; failures back off exponentially and become dead after
//     max_attempts. Effects are idempotent (deleting a missing object succeeds), so at-least-once
//     execution is safe.
//  2. for each app, in worker mode pinned to that app: aborts pending uploads whose lease expired,
//     purges deleted records past their collection's retention (with their history), and drops
//     expired receipts. Each statement handles at most maintainBatch rows.
//  3. delivers committed audit events to the structured log, per chain, at least once.
//
// Job payloads hold scoped IDs only (app, blob id, object key), never content. Every step runs in
// its own transaction with its own scope; a crash at any point leaves state that the next pass
// (on any replica) picks up.

type objectDeletePayload struct {
	BlobID     string   `json:"blob_id"`
	StorageKey string   `json:"storage_key,omitempty"` // single-object blobs (and jobs queued before parts existed)
	Keys       []string `json:"keys,omitempty"`        // every object of the blob, parts included
}

func (p objectDeletePayload) keys() []string {
	if len(p.Keys) > 0 {
		return p.Keys
	}
	return []string{p.StorageKey}
}

// objectKeys lists every object a blob owns: its single object, or each uploaded part.
func objectKeys(ctx context.Context, tx pgx.Tx, app, blobID, storageKey, layout string) ([]string, error) {
	if layout != "parts" {
		return []string{storageKey}, nil
	}
	rows, err := tx.Query(ctx, `SELECT storage_key FROM blob_parts WHERE app = $1 AND blob_id = $2 ORDER BY part_number`, app, blobID)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, pgx.RowTo[string])
}

func enqueueObjectDelete(ctx context.Context, tx pgx.Tx, app, blobID string, keys []string, delay time.Duration) error {
	if len(keys) == 0 {
		return nil
	}
	payload, _ := json.Marshal(objectDeletePayload{BlobID: blobID, Keys: keys})
	_, err := tx.Exec(ctx, `INSERT INTO outbox (app, kind, payload, available_at) VALUES ($1, 'object.delete', $2, $3)`,
		app, payload, time.Now().Add(delay))
	return err
}

type Worker struct {
	core     *Core
	blobs    *Blobs
	Backend  store.Backend // where object deletions go (the blob backend)
	ID       string
	Batch    int
	Lease    time.Duration
	Interval time.Duration

	mu   sync.Mutex
	last WorkerStats
}

// LastStats is the most recent completed pass (metrics read it concurrently).
func (w *Worker) LastStats() WorkerStats {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.last
}

type WorkerStats struct {
	JobsDone, JobsFailed, JobsDead int
	UploadsAborted                 int
	RecordsPurged                  int
	ReceiptsExpired                int
	AuditDelivered                 int
	OldestPendingJob               time.Duration // outbox lag
	AuditUndelivered               int64         // audit delivery lag (events)
	DeadJobs                       int64         // outbox jobs that exhausted their retries (all time)
}

const workerSubject = "system:worker"

func (w *Worker) dispatcher() store.Scope {
	return store.Scope{Subject: workerSubject, Actor: w.ID, Mode: store.ModeDispatcher}
}

func (w *Worker) worker(app string) store.Scope {
	return store.Scope{App: app, Subject: workerSubject, Actor: w.ID, Mode: store.ModeWorker}
}

// Run loops until ctx ends.
func (w *Worker) Run(ctx context.Context) {
	t := time.NewTicker(w.Interval)
	defer t.Stop()
	for {
		stats, err := w.RunOnce(ctx)
		if err != nil && ctx.Err() == nil {
			slog.Error("worker pass failed", "error", err)
		}
		w.mu.Lock()
		w.last = stats
		w.mu.Unlock()
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// RunOnce does one full pass and reports what it did.
func (w *Worker) RunOnce(ctx context.Context) (WorkerStats, error) {
	var s WorkerStats
	if err := w.dispatch(ctx, &s); err != nil {
		return s, fmt.Errorf("outbox: %w", err)
	}
	apps, err := w.apps(ctx)
	if err != nil {
		return s, err
	}
	var failed []error
	for _, app := range apps {
		// One app's failure (a corrupt row, a lock timeout) must not starve the others.
		if err := w.maintain(ctx, app, &s); err != nil {
			failed = append(failed, fmt.Errorf("maintain %s: %w", app, err))
		}
	}
	if err := w.deliverAudit(ctx, &s); err != nil {
		failed = append(failed, fmt.Errorf("audit delivery: %w", err))
	}
	return s, errors.Join(failed...)
}

func (w *Worker) apps(ctx context.Context) ([]string, error) {
	var apps []string
	err := w.core.DB.Run(ctx, w.dispatcher(), func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT app FROM apps WHERE status <> 'legacy' ORDER BY app`)
		if err != nil {
			return err
		}
		apps, err = pgx.CollectRows(rows, pgx.RowTo[string])
		return err
	})
	return apps, err
}

type job struct {
	ID       int64
	App      string
	Kind     string
	Payload  []byte
	Attempts int
	Max      int
}

func (w *Worker) dispatch(ctx context.Context, s *WorkerStats) error {
	var jobs []job
	err := w.core.DB.Run(ctx, w.dispatcher(), func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `UPDATE outbox SET status = 'leased', lease_owner = $1, lease_expires = $2,
			attempts = attempts + 1, updated_at = now()
			WHERE id IN (SELECT id FROM outbox
				WHERE available_at <= now() AND (status = 'pending' OR (status = 'leased' AND lease_expires < now()))
				ORDER BY available_at, id LIMIT $3 FOR UPDATE SKIP LOCKED)
			RETURNING id, app, kind, payload, attempts, max_attempts`, w.ID, time.Now().Add(w.Lease), w.Batch)
		if err != nil {
			return err
		}
		jobs, err = pgx.CollectRows(rows, func(r pgx.CollectableRow) (job, error) {
			var j job
			return j, r.Scan(&j.ID, &j.App, &j.Kind, &j.Payload, &j.Attempts, &j.Max)
		})
		if err != nil {
			return err
		}
		var oldest *time.Time
		if err := tx.QueryRow(ctx, `SELECT min(available_at) FROM outbox WHERE status IN ('pending', 'leased')`).Scan(&oldest); err != nil {
			return err
		}
		if oldest != nil && time.Since(*oldest) > 0 {
			s.OldestPendingJob = time.Since(*oldest)
		}
		if err := tx.QueryRow(ctx, `SELECT count(*) FROM outbox WHERE status = 'dead'`).Scan(&s.DeadJobs); err != nil {
			return err
		}
		_, err = tx.Exec(ctx, `DELETE FROM outbox WHERE id IN (SELECT id FROM outbox WHERE status = 'done'
			AND updated_at < now() - interval '1 day' LIMIT $1 FOR UPDATE SKIP LOCKED)`, maintainBatch)
		return err
	})
	if err != nil {
		return err
	}
	for _, j := range jobs {
		runErr := w.execute(ctx, j)
		err := w.core.DB.Run(ctx, w.dispatcher(), func(tx pgx.Tx) error {
			if runErr == nil {
				_, err := tx.Exec(ctx, `UPDATE outbox SET status = 'done', lease_owner = NULL, lease_expires = NULL,
					last_error = NULL, updated_at = now() WHERE id = $1 AND lease_owner = $2`, j.ID, w.ID)
				return err
			}
			status, backoff := "pending", time.Duration(1<<min(j.Attempts, 10))*time.Second
			if j.Attempts >= j.Max {
				status = "dead"
			}
			// Error text is ours (object store / database), never request content.
			_, err := tx.Exec(ctx, `UPDATE outbox SET status = $3, available_at = $4, lease_owner = NULL, lease_expires = NULL,
				last_error = left($5, 500), updated_at = now() WHERE id = $1 AND lease_owner = $2`,
				j.ID, w.ID, status, time.Now().Add(backoff), runErr.Error())
			return err
		})
		if err != nil {
			return err
		}
		switch {
		case runErr == nil:
			s.JobsDone++
			telemetry.OutboxJobs.Add(ctx, 1, telemetry.Outcome(j.Kind, "done"))
		case j.Attempts >= j.Max:
			s.JobsDead++
			telemetry.OutboxJobs.Add(ctx, 1, telemetry.Outcome(j.Kind, "dead"))
			slog.Error("outbox job dead", "job", j.ID, "app", j.App, "kind", j.Kind, "attempts", j.Attempts, "error", runErr)
		default:
			s.JobsFailed++
			telemetry.OutboxJobs.Add(ctx, 1, telemetry.Outcome(j.Kind, "retry"))
		}
	}
	return nil
}

func (w *Worker) execute(ctx context.Context, j job) error {
	switch j.Kind {
	case "object.delete":
		var p objectDeletePayload
		if err := json.Unmarshal(j.Payload, &p); err != nil {
			return err
		}
		for _, key := range p.keys() {
			if err := w.Backend.Delete(ctx, key); err != nil {
				return err
			}
		}
		// With its objects gone, the wrapped data key only serves backups; drop it from the live row.
		return w.core.DB.Run(ctx, w.worker(j.App), func(tx pgx.Tx) error {
			_, err := tx.Exec(ctx, `UPDATE blobs SET state = 'purged', wrapped_dek = NULL
				WHERE app = $1 AND id = $2 AND state IN ('aborted', 'deleted')`, j.App, p.BlobID)
			return err
		})
	}
	return errors.New("unknown job kind " + j.Kind)
}

// maintainBatch bounds every maintenance statement, so one pass over a large app holds no lock for
// long and a backlog drains over several passes.
const maintainBatch = 500

func (w *Worker) maintain(ctx context.Context, app string, s *WorkerStats) error {
	return w.core.DB.Run(ctx, w.worker(app), func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `UPDATE blobs SET state = 'aborted', lease_owner = NULL, lease_expires = NULL
			WHERE (app, id) IN (SELECT app, id FROM blobs WHERE app = $1 AND state = 'pending' AND lease_expires < now()
			                    LIMIT $2 FOR UPDATE SKIP LOCKED)
			RETURNING id, storage_key, layout`, app, maintainBatch)
		if err != nil {
			return err
		}
		type pending struct{ id, key, layout string }
		expired, err := pgx.CollectRows(rows, func(r pgx.CollectableRow) (pending, error) {
			var p pending
			return p, r.Scan(&p.id, &p.key, &p.layout)
		})
		if err != nil {
			return err
		}
		for _, p := range expired {
			keys, err := objectKeys(ctx, tx, app, p.id, p.key, p.layout)
			if err != nil {
				return err
			}
			if err := enqueueObjectDelete(ctx, tx, app, p.id, keys, 0); err != nil {
				return err
			}
			if _, err := w.core.Audit.Append(ctx, tx, audit.Entry{App: app, Anonymous: workerSubject, Action: "blob.create",
				ResourceType: "blob", ResourceID: p.id, Decision: "error", Reason: "upload lease expired; aborted by sweeper"}); err != nil {
				return err
			}
		}
		s.UploadsAborted += len(expired)

		// Deleted records past their collection's retention are purged with their history.
		rows, err = tx.Query(ctx, `DELETE FROM records WHERE (app, id) IN (
				SELECT r.app, r.id FROM records r JOIN collections c ON c.app = r.app AND c.name = r.collection
				WHERE r.app = $1 AND r.deleted_at < now() - make_interval(days => c.deleted_retention_days)
				LIMIT $2 FOR UPDATE OF r SKIP LOCKED)
			RETURNING id, collection`, app, maintainBatch)
		if err != nil {
			return err
		}
		type purged struct{ id, collection string }
		gone, err := pgx.CollectRows(rows, func(r pgx.CollectableRow) (purged, error) {
			var p purged
			return p, r.Scan(&p.id, &p.collection)
		})
		if err != nil {
			return err
		}
		for _, p := range gone {
			if _, err := w.core.Audit.Append(ctx, tx, audit.Entry{App: app, Anonymous: workerSubject, Action: "record.delete",
				ResourceType: "record", ResourceID: p.id, Decision: "allow", Reason: "deleted record and history purged after retention",
				Details: map[string]any{"collection": p.collection}}); err != nil {
				return err
			}
		}
		s.RecordsPurged += len(gone)

		tag, err := tx.Exec(ctx, `DELETE FROM operation_receipts WHERE (app, subject, actor, op_id) IN (
			SELECT app, subject, actor, op_id FROM operation_receipts WHERE app = $1 AND expires_at < now()
			LIMIT $2 FOR UPDATE SKIP LOCKED)`, app, maintainBatch)
		if err != nil {
			return err
		}
		s.ReceiptsExpired += int(tag.RowsAffected())
		return nil
	})
}

func (w *Worker) deliverAudit(ctx context.Context, s *WorkerStats) error {
	type chain struct {
		name string
		app  *string
		seq  int64
	}
	var chains []chain
	err := w.core.DB.Run(ctx, w.dispatcher(), func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT h.chain, h.app, h.seq - coalesce(d.delivered_seq, 0) FROM audit_heads h
			LEFT JOIN audit_delivery d ON d.chain = h.chain WHERE h.seq > coalesce(d.delivered_seq, 0)`)
		if err != nil {
			return err
		}
		chains, err = pgx.CollectRows(rows, func(r pgx.CollectableRow) (chain, error) {
			var c chain
			return c, r.Scan(&c.name, &c.app, &c.seq)
		})
		return err
	})
	if err != nil {
		return err
	}
	for _, c := range chains {
		s.AuditUndelivered += c.seq
		sc := store.Scope{Subject: workerSubject, Actor: w.ID, Mode: store.ModeGlobal}
		if c.app != nil {
			sc = w.worker(*c.app)
		}
		err := w.core.DB.Run(ctx, sc, func(tx pgx.Tx) error {
			n, err := audit.Deliver(ctx, tx, c.name, c.app, 1000)
			s.AuditDelivered += n
			telemetry.AuditDelivered.Add(ctx, int64(n))
			return err
		})
		if err != nil {
			return err
		}
	}
	s.AuditUndelivered -= int64(s.AuditDelivered)
	return nil
}
