package recovery_test

import (
	"bytes"
	"context"
	"encoding/json"
	"testing"

	"github.com/paulmalmquist/storage_relspace/internal/backup"
	"github.com/paulmalmquist/storage_relspace/internal/crypto"
	"github.com/paulmalmquist/storage_relspace/internal/markings"
	"github.com/paulmalmquist/storage_relspace/internal/recovery"
	"github.com/paulmalmquist/storage_relspace/internal/service"
	"github.com/paulmalmquist/storage_relspace/internal/testenv"
)

func TestRecoveryDrillRestoresMixedDataAndOlderKeys(t *testing.T) {
	src, ctx := testenv.New(t), context.Background()
	u := src.Ctx(t, "engineer@rel.test")
	if _, err := src.C.Records.CreateCollection(ctx, src.Ctx(t, "admin@rel.test"), service.CollectionInput{Name: "plain", Marking: markings.None()}); err != nil {
		t.Fatal(err)
	}
	record, err := src.C.Records.Create(ctx, u, "plain", service.RecordInput{Data: map[string]any{"state": "draft"}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := src.C.Records.Update(ctx, u, "plain", record.ID, service.RecordInput{Data: map[string]any{"state": "saved"}}, 1); err != nil {
		t.Fatal(err)
	}
	if _, err := src.C.Blobs.Put(ctx, u, []byte("controlled attachment"), service.BlobInput{Marking: markings.MustParse("CUI//SP-EXPT")}); err != nil {
		t.Fatal(err)
	}
	pending, err := src.C.Blobs.CreateSession(ctx, u, service.BlobInput{Marking: markings.None(), DeclaredSize: 2})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := src.C.Blobs.PutPart(ctx, u, pending.ID, 1, bytes.NewBufferString("ok")); err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	if _, err := backup.Export(ctx, src.Migrator, src.C.Backend, testenv.App, dir, "test", "test", src.C.KMS); err != nil {
		t.Fatal(err)
	}
	if _, err := crypto.RotateLocalKeyring(src.Keyring); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		dst := testenv.EmptyDatabase(t, src.Keyring)
		report, err := recovery.Drill(ctx, dst.C, dst.Migrator, dir, "test-drill")
		if err != nil || !report.Passed || !report.Restored || report.Usage.Drift || !report.Audit.OK || report.Decrypt.Blobs != 1 || report.Decrypt.Records != 1 {
			t.Fatalf("drill report %+v %v", report, err)
		}
		if report.SnapshotAt.IsZero() || report.Seconds["total"] <= 0 || report.Seconds["dry_run"] <= 0 {
			t.Fatalf("drill lacks timing evidence %+v", report)
		}
		user := dst.Ctx(t, "engineer@rel.test")
		if _, err := dst.C.Blobs.CompleteSession(ctx, user, pending.ID); err != nil {
			t.Fatal(err)
		}
		_, body, err := dst.C.Blobs.ReadAll(ctx, user, pending.ID)
		if err != nil || string(body) != "ok" {
			t.Fatalf("pending upload did not recover: %q %v", body, err)
		}
		raw, _ := json.Marshal(report)
		t.Logf("drill_report=%s", raw)
		if _, err := recovery.Drill(ctx, dst.C, dst.Migrator, dir, "test-drill"); err == nil {
			t.Fatal("drill overwrote an existing app")
		}
	}
	if _, err := recovery.Drill(ctx, src.C, src.Migrator, dir, "test-drill"); err == nil {
		t.Fatal("drill accepted the source database")
	}
}
