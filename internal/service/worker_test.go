package service_test

import (
	"context"
	"errors"
	"testing"

	"github.com/paulmalmquist/storage_relspace/internal/service"
	"github.com/paulmalmquist/storage_relspace/internal/store"
	"github.com/paulmalmquist/storage_relspace/internal/testenv"
)

type flakyBackend struct {
	store.Backend
	fail int
}

func (f *flakyBackend) Delete(ctx context.Context, key string) error {
	if f.fail > 0 {
		f.fail--
		return errors.New("object store unavailable")
	}
	return f.Backend.Delete(ctx, key)
}

// Outbox jobs retry with backoff, become dead after max_attempts, and record only our own error
// text; a dead job is visible for operators.
func TestOutboxRetriesAndDeadLetters(t *testing.T) {
	env, ctx := testenv.New(t), context.Background()
	eng := env.Ctx(t, "engineer@rel.test")
	flaky := &flakyBackend{Backend: env.C.Backend, fail: 1}
	env.C.Worker.Backend = flaky
	m := must[*service.BlobMeta](t)(env.C.Blobs.Put(ctx, eng, []byte("x"), service.BlobInput{}))
	if err := env.C.Blobs.Delete(ctx, eng, m.ID, false); err != nil {
		t.Fatal(err)
	}
	s := must[service.WorkerStats](t)(env.C.Worker.RunOnce(ctx))
	if s.JobsFailed != 1 {
		t.Fatalf("first attempt: %+v", s)
	}
	env.Admin(t, `UPDATE outbox SET available_at = now()`) // skip the backoff
	s = must[service.WorkerStats](t)(env.C.Worker.RunOnce(ctx))
	if s.JobsDone != 1 {
		t.Fatalf("retry: %+v", s)
	}
	var state string
	_ = env.Migrator.QueryRow(ctx, `SELECT state FROM blobs WHERE id = $1`, m.ID).Scan(&state)
	if state != "purged" {
		t.Fatalf("state %s", state)
	}

	m2 := must[*service.BlobMeta](t)(env.C.Blobs.Put(ctx, eng, []byte("y"), service.BlobInput{}))
	flaky.fail = 100
	_ = env.C.Blobs.Delete(ctx, eng, m2.ID, false)
	env.Admin(t, `UPDATE outbox SET max_attempts = 2 WHERE status = 'pending'`)
	for i := 0; i < 2; i++ {
		_, _ = env.C.Worker.RunOnce(ctx)
		env.Admin(t, `UPDATE outbox SET available_at = now() WHERE status = 'pending'`)
	}
	var status, lastErr string
	var payload string
	_ = env.Migrator.QueryRow(ctx, `SELECT status, last_error, payload::text FROM outbox WHERE payload->>'blob_id' = $1`, m2.ID).
		Scan(&status, &lastErr, &payload)
	if status != "dead" || lastErr != "object store unavailable" {
		t.Fatalf("job %s: %q", status, lastErr)
	}
	t.Logf("dead job payload (IDs only): %s", payload)
}

// A worker's scope is pinned to one app: running maintenance for one app never touches another.
func TestWorkerIsPinnedPerApp(t *testing.T) {
	env, ctx := testenv.New(t), context.Background()
	u, _, err := env.C.Blobs.Begin(ctx, env.CtxIn(t, testenv.Other, "outsider@rel.test"), service.BlobInput{DeclaredSize: -1})
	if err != nil {
		t.Fatal(err)
	}
	env.Admin(t, `UPDATE blobs SET lease_expires = now() - interval '1 minute'`)
	s := must[service.WorkerStats](t)(env.C.Worker.RunOnce(ctx))
	if s.UploadsAborted != 1 {
		t.Fatalf("%+v", s)
	}
	var app string
	_ = env.Migrator.QueryRow(ctx, `SELECT app FROM outbox`).Scan(&app)
	if app != testenv.Other {
		t.Fatalf("job enqueued for %s", app)
	}
	u.Abort("test")
}
