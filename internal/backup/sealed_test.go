package backup_test

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/paulmalmquist/storage_relspace/internal/backup"
	"github.com/paulmalmquist/storage_relspace/internal/markings"
	"github.com/paulmalmquist/storage_relspace/internal/service"
	"github.com/paulmalmquist/storage_relspace/internal/testenv"
)

func TestSealedExportRecoversPlainCollectionsWithoutPlaintextFiles(t *testing.T) {
	src, ctx := testenv.New(t), context.Background()
	adm, eng := src.Ctx(t, "admin@rel.test"), src.Ctx(t, "engineer@rel.test")
	if _, err := src.C.Records.CreateCollection(ctx, adm, service.CollectionInput{Name: "plain", Marking: markings.None(), IndexedFields: []string{"tag"}, UniqueFields: []string{"tag"}}); err != nil {
		t.Fatal(err)
	}
	secret := "private-export-payload-marker-52989"
	rec, err := src.C.Records.Create(ctx, eng, "plain", service.RecordInput{Data: map[string]any{"tag": secret}})
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	m, err := backup.Export(ctx, src.Migrator, src.C.Backend, testenv.App, dir, "test", "test", src.C.KMS)
	if err != nil {
		t.Fatal(err)
	}
	if m.FormatVersion != 2 {
		t.Fatalf("format %d is not sealed", m.FormatVersion)
	}
	if err := filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		raw, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		if bytes.Contains(raw, []byte(secret)) || bytes.Contains(raw, []byte("engineer@rel.test")) {
			t.Errorf("plaintext table data in %s", path)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	_, report, err := backup.Validate(dir)
	if err != nil || !report.OK() {
		t.Fatalf("offline validation: %+v %v", report, err)
	}
	dst := testenv.EmptyDatabase(t, src.Keyring)
	if _, err := backup.Restore(ctx, dst.Migrator, dst.C.Backend, dir, true, dst.C.KMS); err != nil {
		t.Fatal(err)
	}
	var n int
	if err := dst.Migrator.QueryRow(ctx, `SELECT count(*) FROM apps WHERE app=$1`, testenv.App).Scan(&n); err != nil || n != 0 {
		t.Fatalf("dry run wrote app: %d %v", n, err)
	}
	if _, err := backup.Restore(ctx, dst.Migrator, dst.C.Backend, dir, false, dst.C.KMS); err != nil {
		t.Fatal(err)
	}
	got, err := dst.C.Records.Get(ctx, dst.Ctx(t, "engineer@rel.test"), "plain", rec.ID)
	if err != nil || got.Data["tag"] != secret {
		t.Fatalf("restored plaintext collection: %+v %v", got, err)
	}
	v, err := dst.C.VerifyApp(ctx, testenv.App, true)
	if err != nil || len(v.Problems) > 0 {
		t.Fatalf("deep verify: %+v %v", v, err)
	}
}

func TestSealedExportDoesNotExposeRegistryOrSchema(t *testing.T) {
	src, ctx := testenv.New(t), context.Background()
	dir := t.TempDir()
	if _, err := backup.Export(ctx, src.Migrator, src.C.Backend, testenv.App, dir, "test", "test", src.C.KMS); err != nil {
		t.Fatal(err)
	}
	if err := filepath.WalkDir(filepath.Join(dir, "tables"), func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		raw, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		if bytes.Contains(raw, []byte("admin@rel.test")) {
			t.Errorf("registry plaintext in %s", path)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}
