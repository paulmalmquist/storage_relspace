package service

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/paulmalmquist/storage_relspace/internal/audit"
	"github.com/paulmalmquist/storage_relspace/internal/store"
)

// The worker is Strongbox's single background mechanism. Each pass:
//
//  1. dispatches outbox jobs (object deletion): claimed with FOR UPDATE SKIP LOCKED under a lease,
//     executed, then marked done; failures back off exponentially and become dead after
//     max_attempts. Effects are idempotent (deleting a missing object succeeds), so at-least-once
//     execution is safe.
//  2. for each app, in worker mode pinned to that app: aborts pending uploads whose lease expired,
//     trims record history to each collection's history_limit, and drops expired receipts.
//  3. delivers committed audit events to the structured log, per chain, at least once.
//
// Job payloads hold scoped IDs only (app, blob id, object key), never content. Every step runs in
// its own transaction with its own scope; a crash at any point leaves state that the next pass
// (on any replica) picks up.

type objectDeletePayload struct {
	BlobID     string `json:"blob_id"`
	StorageKey string `json:"storage_key"`
}

func enqueueObjectDelete(ctx context.Context, tx pgx.Tx, app, blobID, key string, delay time.Duration) error {
	payload, _ := json.Marshal(objectDeletePayload{BlobID: blobID, StorageKey: key})
	_, err := tx.Exec(ctx, `INSERT INTO outbox (app, kind, payload, available_at) VALUES ($1, 'object.delete', $2, $3)`,
		app, payload, time.Now().Add(delay))
	return err
}

type Worker struct {
	core      *Core
	blobs     *Blobs
	Backend   store.Backend // where object deletions go (the blob backend)
	ID        string
	Batch     int
	Lease     time.Duration
	Interval  time.Duration
	LastStats WorkerStats
}

type WorkerStats struct {
	JobsDone, JobsFailed, JobsDead int
	UploadsAborted                 int
	RevisionsPruned                int
	ReceiptsExpired                int
	AuditDelivered                 int
	OldestPendingJob               time.Duration // outbox lag
	AuditUndelivered               int64         // audit delivery lag (events)
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
		if stats, err := w.RunOnce(ctx); err != nil && ctx.Err() == nil {
			slog.Error("worker pass failed", "error", err)
		} else {
			w.LastStats = stats
		}
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
	for _, app := range apps {
		if err := w.maintain(ctx, app, &s); err != nil {
			return s, fmt.Errorf("maintain %s: %w", app, err)
		}
	}
	if err := w.deliverAudit(ctx, &s); err != nil {
		return s, fmt.Errorf("audit delivery: %w", err)
	}
	return s, nil
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
		return nil
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
		case j.Attempts >= j.Max:
			s.JobsDead++
			slog.Error("outbox job dead", "job", j.ID, "app", j.App, "kind", j.Kind, "attempts", j.Attempts, "error", runErr)
		default:
			s.JobsFailed++
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
		if err := w.Backend.Delete(ctx, p.StorageKey); err != nil {
			return err
		}
		return w.core.DB.Run(ctx, w.worker(j.App), func(tx pgx.Tx) error {
			_, err := tx.Exec(ctx, `UPDATE blobs SET state = 'purged' WHERE app = $1 AND id = $2 AND state IN ('aborted', 'deleted')`,
				j.App, p.BlobID)
			return err
		})
	}
	return errors.New("unknown job kind " + j.Kind)
}

func (w *Worker) maintain(ctx context.Context, app string, s *WorkerStats) error {
	return w.core.DB.Run(ctx, w.worker(app), func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `UPDATE blobs SET state = 'aborted', lease_owner = NULL, lease_expires = NULL
			WHERE app = $1 AND state = 'pending' AND lease_expires < now() RETURNING id, storage_key`, app)
		if err != nil {
			return err
		}
		type pending struct{ id, key string }
		expired, err := pgx.CollectRows(rows, func(r pgx.CollectableRow) (pending, error) {
			var p pending
			return p, r.Scan(&p.id, &p.key)
		})
		if err != nil {
			return err
		}
		for _, p := range expired {
			if err := enqueueObjectDelete(ctx, tx, app, p.id, p.key, 0); err != nil {
				return err
			}
			if _, err := w.core.Audit.Append(ctx, tx, audit.Entry{App: app, Anonymous: workerSubject, Action: "blob.create",
				ResourceType: "blob", ResourceID: p.id, Decision: "error", Reason: "upload lease expired; aborted by sweeper"}); err != nil {
				return err
			}
		}
		s.UploadsAborted += len(expired)
		tag, err := tx.Exec(ctx, `DELETE FROM record_revisions rv USING collections c
			WHERE rv.app = $1 AND c.app = rv.app AND c.name = rv.collection
			  AND rv.version <= (SELECT r.version FROM records r WHERE r.app = rv.app AND r.id = rv.record_id) - c.history_limit`, app)
		if err != nil {
			return err
		}
		s.RevisionsPruned += int(tag.RowsAffected())
		tag, err = tx.Exec(ctx, `DELETE FROM operation_receipts WHERE app = $1 AND expires_at < now()`, app)
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
			return err
		})
		if err != nil {
			return err
		}
	}
	s.AuditUndelivered -= int64(s.AuditDelivered)
	return nil
}
