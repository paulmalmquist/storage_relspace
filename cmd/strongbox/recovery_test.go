package main

import (
	"context"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/paulmalmquist/storage_relspace/internal/admin"
	"github.com/paulmalmquist/storage_relspace/internal/backup"
	"github.com/paulmalmquist/storage_relspace/internal/markings"
	"github.com/paulmalmquist/storage_relspace/internal/recovery"
	"github.com/paulmalmquist/storage_relspace/internal/service"
	"github.com/paulmalmquist/storage_relspace/internal/store"
	"github.com/paulmalmquist/storage_relspace/internal/testenv"
)

func commandOutput(t *testing.T, fn func() error) []byte {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	previous := os.Stdout
	os.Stdout = w
	defer func() { os.Stdout = previous }()
	done := make(chan []byte, 1)
	go func() { raw, _ := io.ReadAll(r); _ = r.Close(); done <- raw }()
	callErr := fn()
	_ = w.Close()
	raw := <-done
	if callErr != nil {
		t.Fatalf("command failed: %v\n%s", callErr, raw)
	}
	return raw
}
func localConfig(t *testing.T, e *testenv.Env) {
	t.Helper()
	for k, v := range map[string]string{
		"STRONGBOX_ENV": "test", "STRONGBOX_APP_ENV": "test", "STRONGBOX_DEV_JWT_SECRET": testenv.Secret,
		"STRONGBOX_DATABASE_URL": e.RuntimeURL, "STRONGBOX_MIGRATION_DATABASE_URL": e.URL, "STRONGBOX_DB_SCHEMA": e.Schema,
		"STRONGBOX_KMS_BACKEND": "local", "STRONGBOX_LOCAL_KEYRING_PATH": e.Keyring,
		"STRONGBOX_BLOB_BACKEND": "local", "STRONGBOX_BLOB_LOCAL_PATH": e.BlobDir,
	} {
		t.Setenv(k, v)
	}
}
func TestRecoveryCommandsUseSealedExportsAndDryRunReconciliation(t *testing.T) {
	src, ctx := testenv.New(t), context.Background()
	if _, err := src.C.Records.CreateCollection(ctx, src.Ctx(t, "admin@rel.test"), service.CollectionInput{Name: "plain", Marking: markings.None()}); err != nil {
		t.Fatal(err)
	}
	if _, err := src.C.Records.Create(ctx, src.Ctx(t, "engineer@rel.test"), "plain", service.RecordInput{Data: map[string]any{"value": "saved"}}); err != nil {
		t.Fatal(err)
	}
	localConfig(t, src)
	dir := t.TempDir()
	raw := commandOutput(t, func() error { return cmdExport(ctx, []string{"-app", testenv.App, "-out", dir}) })
	var manifest backup.Manifest
	if err := json.Unmarshal(raw, &manifest); err != nil || manifest.FormatVersion != 2 {
		t.Fatalf("CLI did not seal export: %v %s", err, raw)
	}
	// Both validators work with no database available; authenticated local validation needs just keys.
	t.Setenv("STRONGBOX_DATABASE_URL", "postgres://unused@127.0.0.1:1/unused")
	t.Setenv("STRONGBOX_MIGRATION_DATABASE_URL", "postgres://unused@127.0.0.1:1/unused")
	commandOutput(t, func() error { return cmdValidateExport(ctx, []string{"-in", dir}) })
	commandOutput(t, func() error { return cmdValidateExport(ctx, []string{"-in", dir, "-authenticate"}) })
	dst := testenv.EmptyDatabase(t, src.Keyring)
	localConfig(t, dst)
	commandOutput(t, func() error { return cmdRestore(ctx, []string{"-in", dir, "-dry-run"}) })
	raw = commandOutput(t, func() error { return cmdRestoreDrill(ctx, []string{"-in", dir}) })
	var drill recovery.Report
	if err := json.Unmarshal(raw, &drill); err != nil || !drill.Passed {
		t.Fatalf("CLI drill: %v %s", err, raw)
	}
	key := "apps/acme/test/blb_orphan/cipher"
	w, err := dst.C.Backend.OpenWriter(ctx, key)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = w.Write([]byte("orphan"))
	if err := w.Commit(); err != nil {
		t.Fatal(err)
	}
	old := time.Now().Add(-2 * store.OrphanGrace)
	if err := os.Chtimes(filepath.Join(dst.BlobDir, key), old, old); err != nil {
		t.Fatal(err)
	}
	raw = commandOutput(t, func() error { return cmdReconcile(ctx, []string{"-app", testenv.App}) })
	var report admin.ReconcileReport
	if err := json.Unmarshal(raw, &report); err != nil || report.Orphans != 1 || report.Queued != 0 || !report.DryRun {
		t.Fatalf("CLI dry reconciliation: %v %s", err, raw)
	}
	commandOutput(t, func() error { return cmdReconcile(ctx, []string{"-app", testenv.App, "-apply"}) })
	if _, err := dst.C.Worker.RunOnce(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := dst.C.Backend.Read(ctx, key); err == nil {
		t.Fatal("CLI cleanup did not reach worker")
	}
}
