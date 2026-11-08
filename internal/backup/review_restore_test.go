package backup_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/paulmalmquist/storage_relspace/internal/backup"
	"github.com/paulmalmquist/storage_relspace/internal/markings"
	"github.com/paulmalmquist/storage_relspace/internal/service"
	"github.com/paulmalmquist/storage_relspace/internal/store"
	"github.com/paulmalmquist/storage_relspace/internal/testenv"
)

// Recalculate the public, unkeyed manifest after an intentional input mutation.
// Restore must validate scope/structure independently of these transport digests.
func reviewRewriteTable(t *testing.T, dir, name string, change func([]byte) []byte) {
	t.Helper()
	path := filepath.Join(dir, "tables", name+".ndjson")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	raw = change(raw)
	if err := os.WriteFile(path, raw, 0600); err != nil {
		t.Fatal(err)
	}
	reviewManifest(t, dir, func(m *backup.Manifest) {
		for i := range m.Tables {
			if m.Tables[i].Name == name {
				sum := sha256.Sum256(raw)
				m.Tables[i].SHA256 = hex.EncodeToString(sum[:])
				m.Tables[i].Rows = int64(bytes.Count(raw, []byte{'\n'}))
			}
		}
	})
}

func reviewManifest(t *testing.T, dir string, change func(*backup.Manifest)) {
	t.Helper()
	path := filepath.Join(dir, "manifest.json")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var m backup.Manifest
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	change(&m)
	raw, err = json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, raw, 0600); err != nil {
		t.Fatal(err)
	}
}

func reviewExport(t *testing.T, src *testenv.Env) string {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "export")
	if _, err := backup.Export(context.Background(), src.Migrator, src.C.Backend, testenv.App, dir, "review", "2e35159"); err != nil {
		t.Fatal(err)
	}
	return dir
}

func TestReviewRestoreRejectsForeignAppRows(t *testing.T) {
	ctx, src := context.Background(), testenv.New(t)
	dir := reviewExport(t, src)
	reviewRewriteTable(t, dir, "app_members", func(raw []byte) []byte {
		return append(raw, []byte(`{"app":"rival:test","subject":"engineer@rel.test","role":"admin","added_by":"review"}`+"\n")...)
	})
	dst := testenv.Empty(t, src.Keyring)
	dst.Admin(t, `INSERT INTO apps (app, created_by) VALUES ($1, 'existing-operator')`, testenv.Other)
	_, err := backup.Restore(ctx, dst.Migrator, dst.C.Backend, dir, false)
	if err == nil {
		var count int
		if err := dst.Migrator.QueryRow(ctx, `SELECT count(*) FROM app_members WHERE app=$1 AND subject='engineer@rel.test' AND role='admin'`, testenv.Other).Scan(&count); err != nil {
			t.Fatal(err)
		}
		t.Fatalf("foreign-app row accepted; injected %d administrator(s) into an existing app", count)
	}
	var count int
	if err := dst.Migrator.QueryRow(ctx, `SELECT count(*) FROM app_members WHERE app=$1`, testenv.Other).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 0 {
		t.Fatal("rejected restore changed another app")
	}
}

type reviewCountingBackend struct {
	store.Backend
	writes int
}

func (b *reviewCountingBackend) OpenWriter(ctx context.Context, key string) (store.Writer, error) {
	b.writes++
	return b.Backend.OpenWriter(ctx, key)
}

func TestReviewRefusedRestoreDoesNotWriteObjects(t *testing.T) {
	ctx, src := context.Background(), testenv.New(t)
	if _, err := src.C.Blobs.Put(ctx, src.Ctx(t, "engineer@rel.test"), []byte("original content"), service.BlobInput{Marking: markings.None()}); err != nil {
		t.Fatal(err)
	}
	dir := reviewExport(t, src)
	dst := testenv.New(t) // target app already exists, but its object store is empty
	backend := &reviewCountingBackend{Backend: dst.C.Backend}
	if _, err := backup.Restore(ctx, dst.Migrator, backend, dir, false); err == nil {
		t.Fatal("existing app was accepted")
	}
	if backend.writes != 0 {
		t.Fatalf("refused restore opened %d object writers before checking target app", backend.writes)
	}
}
