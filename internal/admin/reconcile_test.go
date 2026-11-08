package admin_test

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/paulmalmquist/storage_relspace/internal/admin"
	"github.com/paulmalmquist/storage_relspace/internal/markings"
	"github.com/paulmalmquist/storage_relspace/internal/service"
	"github.com/paulmalmquist/storage_relspace/internal/store"
	"github.com/paulmalmquist/storage_relspace/internal/testenv"
)

func maintenance(e *testenv.Env) *admin.Admin {
	return &admin.Admin{Pool: e.Migrator, Actor: "test-reconciliation", Stripes: e.C.Config.AuditStripes}
}
func oldObject(t *testing.T, e *testenv.Env, key string) {
	t.Helper()
	w, err := e.C.Backend.OpenWriter(context.Background(), key)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write([]byte("test-ciphertext-orphan")); err != nil {
		t.Fatal(err)
	}
	if err := w.Commit(); err != nil {
		t.Fatal(err)
	}
	before := time.Now().Add(-2 * store.OrphanGrace)
	if err := os.Chtimes(filepath.Join(e.BlobDir, key), before, before); err != nil {
		t.Fatal(err)
	}
}
func TestReconcileDryRunAndQueuedGenerationCleanup(t *testing.T) {
	e, ctx := testenv.New(t), context.Background()
	a := maintenance(e)
	key := "apps/acme/test/blb_orphan/cipher"
	foreign := "apps/rival/test/blb_orphan/cipher"
	oldObject(t, e, key)
	oldObject(t, e, foreign)
	dry, err := a.Reconcile(ctx, e.C.Backend, testenv.App, admin.ReconcileOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if dry.Orphans != 1 || dry.Queued != 0 || !dry.DryRun {
		t.Fatalf("dry run %+v", dry)
	}
	if _, err := e.C.Backend.Read(ctx, key); err != nil {
		t.Fatal("dry run removed object", err)
	}
	applied, err := a.Reconcile(ctx, e.C.Backend, testenv.App, admin.ReconcileOptions{Apply: true})
	if err != nil || applied.Queued != 1 {
		t.Fatalf("apply %+v %v", applied, err)
	}
	again, err := a.Reconcile(ctx, e.C.Backend, testenv.App, admin.ReconcileOptions{Apply: true})
	if err != nil || again.Queued != 0 {
		t.Fatalf("duplicate cleanup job %+v %v", again, err)
	}
	if _, err := e.C.Worker.RunOnce(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := e.C.Backend.Read(ctx, key); err == nil {
		t.Fatal("worker did not remove orphan")
	}
	if r, err := e.C.Backend.Read(ctx, foreign); err != nil {
		t.Fatal("another app was changed", err)
	} else {
		_ = r.Close()
	}
}
func TestReconcileProtectsPendingUploadsAndChangedGenerations(t *testing.T) {
	e, ctx := testenv.New(t), context.Background()
	a := maintenance(e)
	u := e.Ctx(t, "engineer@rel.test")
	session, err := e.C.Blobs.CreateSession(ctx, u, service.BlobInput{Marking: markings.None(), DeclaredSize: 1})
	if err != nil {
		t.Fatal(err)
	}
	pending := "apps/acme/test/" + session.ID + "/uncommitted-attempt"
	oldObject(t, e, pending)
	candidate := "apps/acme/test/blb_orphan/cipher"
	oldObject(t, e, candidate)
	report, err := a.Reconcile(ctx, e.C.Backend, testenv.App, admin.ReconcileOptions{Apply: true})
	if err != nil || report.Orphans != 1 {
		t.Fatalf("pending attempt not protected %+v %v", report, err)
	}
	if err := os.WriteFile(filepath.Join(e.BlobDir, candidate), []byte("changed generation"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := e.C.Worker.RunOnce(ctx); err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{pending, candidate} {
		r, err := e.C.Backend.Read(ctx, key)
		if err != nil {
			t.Fatal("protected generation removed", key, err)
		}
		_ = r.Close()
	}
}
func TestReconcileMissingFilesAndCursorScope(t *testing.T) {
	e, ctx := testenv.New(t), context.Background()
	a := maintenance(e)
	blob, err := e.C.Blobs.Put(ctx, e.Ctx(t, "engineer@rel.test"), []byte("data"), service.BlobInput{Marking: markings.None()})
	if err != nil {
		t.Fatal(err)
	}
	var key string
	if err := e.Migrator.QueryRow(ctx, `SELECT storage_key FROM blobs WHERE app=$1 AND id=$2`, testenv.App, blob.ID).Scan(&key); err != nil {
		t.Fatal(err)
	}
	if err := e.C.Backend.Delete(ctx, key); err != nil {
		t.Fatal(err)
	}
	report, err := a.Reconcile(ctx, e.C.Backend, testenv.App, admin.ReconcileOptions{Limit: 1})
	if err != nil || report.Missing != 1 || report.Next == "" {
		t.Fatalf("missing-file page %+v %v", report, err)
	}
	if _, err := a.Reconcile(ctx, e.C.Backend, testenv.Other, admin.ReconcileOptions{Limit: 1, Cursor: report.Next}); err == nil {
		t.Fatal("another app accepted cursor")
	}
	if _, err := a.Reconcile(ctx, e.C.Backend, testenv.App, admin.ReconcileOptions{Limit: 1, Cursor: report.Next}); err != nil {
		t.Fatal(err)
	}
}
func TestReconcileWorkerRechecksReferencesAndScope(t *testing.T) {
	e, ctx := testenv.New(t), context.Background()
	a := maintenance(e)
	key := "apps/acme/test/blb_future/cipher"
	oldObject(t, e, key)
	report, err := a.Reconcile(ctx, e.C.Backend, testenv.App, admin.ReconcileOptions{Apply: true})
	if err != nil || report.Queued != 1 {
		t.Fatalf("queue %+v %v", report, err)
	}
	// A reference arriving after the scan must veto the queued deletion.
	// Use a real pending row to protect its entire attempt prefix without fabricating ciphertext metadata.
	session, err := e.C.Blobs.CreateSession(ctx, e.Ctx(t, "engineer@rel.test"), service.BlobInput{Marking: markings.None(), DeclaredSize: 1})
	if err != nil {
		t.Fatal(err)
	}
	e.Admin(t, `UPDATE blobs SET id='blb_future' WHERE app=$1 AND id=$2`, testenv.App, session.ID)
	if _, err := e.C.Worker.RunOnce(ctx); err != nil {
		t.Fatal(err)
	}
	r, err := e.C.Backend.Read(ctx, key)
	if err != nil {
		t.Fatal("late reference was ignored", err)
	}
	_ = r.Close()
	foreign := "apps/rival/test/blb_orphan/cipher"
	oldObject(t, e, foreign)
	info, err := e.C.Backend.(store.Inventory).StatObject(ctx, foreign)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(info)
	e.Admin(t, `INSERT INTO outbox(app,kind,payload,max_attempts) VALUES($1,'object.orphan_delete',$2,1)`, testenv.App, raw)
	if _, err := e.C.Worker.RunOnce(ctx); err != nil {
		t.Fatal(err)
	}
	r, err = e.C.Backend.Read(ctx, foreign)
	if err != nil {
		t.Fatal("foreign object deleted", err)
	}
	_ = r.Close()
}
