package backup_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/paulmalmquist/storage_relspace/internal/backup"
	"github.com/paulmalmquist/storage_relspace/internal/crypto"
	"github.com/paulmalmquist/storage_relspace/internal/markings"
	"github.com/paulmalmquist/storage_relspace/internal/service"
	"github.com/paulmalmquist/storage_relspace/internal/store"
	"github.com/paulmalmquist/storage_relspace/internal/testenv"
)

func TestSealedExportRecoversPlainCollectionsWithoutPlaintextFiles(t *testing.T) {
	src, ctx := testenv.New(t), context.Background()
	adm, eng := src.Ctx(t, "admin@rel.test"), src.Ctx(t, "engineer@rel.test")
	if _, err := src.C.Records.CreateCollection(ctx, adm, service.CollectionInput{Name: "plain", Marking: markings.None(), IndexedFields: []string{"tag"}, UniqueFields: []string{"tag"}}); err != nil {
		t.Fatal(err)
	}
	secret := "private-export-payload-marker-52989"
	rec, err := src.C.Records.Create(ctx, eng, "plain", service.RecordInput{Data: map[string]any{"tag": secret, "payload": strings.Repeat(secret, 5000)}})
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
	if err != nil || got.Data["tag"] != secret || got.Data["payload"] != strings.Repeat(secret, 5000) {
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

func TestSealedRestoreRejectsRehashedTamperingBeforeWrites(t *testing.T) {
	for _, attack := range []string{"table", "source", "app", "export-id", "table-name", "rows", "object-inventory"} {
		t.Run(attack, func(t *testing.T) {
			src, ctx := testenv.New(t), context.Background()
			dir := t.TempDir()
			m, err := backup.Export(ctx, src.Migrator, src.C.Backend, testenv.App, dir, "test", "test", src.C.KMS)
			if err != nil {
				t.Fatal(err)
			}
			reviewManifest(t, dir, func(changed *backup.Manifest) {
				switch attack {
				case "table":
					path := filepath.Join(dir, changed.Tables[0].File)
					raw, e := os.ReadFile(path)
					if e != nil {
						t.Fatal(e)
					}
					raw[len(raw)-1] ^= 1
					if err := os.WriteFile(path, raw, 0600); err != nil {
						t.Fatal(err)
					}
					sum := sha256.Sum256(raw)
					changed.Tables[0].SHA256 = hex.EncodeToString(sum[:])
				case "source":
					changed.Source.Database = "substituted"
				case "app":
					changed.App = testenv.Other
				case "export-id":
					changed.Encryption.ID = "ex_00000000000000000000000000000000"
				case "table-name":
					changed.Tables[0].File = "tables/../apps.ndjson.sbx"
				case "rows":
					changed.Tables[0].Rows++
				case "object-inventory":
					changed.Objects.Count++
				}
			})
			dst := testenv.EmptyDatabase(t, src.Keyring)
			backend := &reviewCountingBackend{Backend: dst.C.Backend}
			if _, err := backup.Restore(ctx, dst.Migrator, backend, dir, false, dst.C.KMS); err == nil {
				t.Fatal("tampered sealed bundle accepted")
			}
			if backend.writes != 0 {
				t.Fatal("refused restore wrote objects")
			}
			var n int
			if err := dst.Migrator.QueryRow(ctx, `SELECT count(*) FROM apps WHERE app=$1`, m.App).Scan(&n); err != nil || n != 0 {
				t.Fatalf("refused restore wrote app: %d %v", n, err)
			}
		})
	}
}

func TestSealedValidateAuthenticatesOfflineAndNeedsCorrectKey(t *testing.T) {
	src, ctx := testenv.New(t), context.Background()
	dir := t.TempDir()
	if _, err := backup.Export(ctx, src.Migrator, src.C.Backend, testenv.App, dir, "test", "test", src.C.KMS); err != nil {
		t.Fatal(err)
	}
	_, transport, err := backup.Validate(dir)
	if err != nil || !transport.OK() || transport.Authenticated || transport.Level != "transport" {
		t.Fatalf("transport report %+v %v", transport, err)
	}
	_, full, err := backup.ValidateAuthenticated(ctx, dir, src.C.KMS)
	if err != nil || !full.OK() || !full.Authenticated || full.Level != "authenticated" {
		t.Fatalf("authenticated report %+v %v", full, err)
	}
	other := testenv.New(t)
	if _, _, err := backup.ValidateAuthenticated(ctx, dir, other.C.KMS); err == nil {
		t.Fatal("unrelated keyring authenticated export")
	}
	// Retiring the active KEK must leave existing bundles readable through the old version.
	if _, err := crypto.RotateLocalKeyring(src.Keyring); err != nil {
		t.Fatal(err)
	}
	rotated, err := crypto.LoadLocalKeyring(src.Keyring)
	if err != nil {
		t.Fatal(err)
	}
	if _, report, err := backup.ValidateAuthenticated(ctx, dir, rotated); err != nil || !report.OK() {
		t.Fatalf("old KEK recovery: %+v %v", report, err)
	}
}

func TestSealedRecoveryPreservesReceiptsAndPendingOutsideEffects(t *testing.T) {
	src, ctx := testenv.New(t), context.Background()
	owner := src.Ctx(t, "engineer@rel.test")
	if _, err := src.C.Records.CreateCollection(ctx, src.Ctx(t, "admin@rel.test"), service.CollectionInput{Name: "plain", Marking: markings.None()}); err != nil {
		t.Fatal(err)
	}
	owner.OpID = "receipt-preserved-after-restore"
	input := service.RecordInput{Data: map[string]any{"state": "saved"}}
	original, err := src.C.Records.Create(ctx, owner, "plain", input)
	if err != nil {
		t.Fatal(err)
	}
	blobOwner := src.Ctx(t, "engineer@rel.test")
	blob, err := src.C.Blobs.Put(ctx, blobOwner, []byte("deleted attachment"), service.BlobInput{Marking: markings.None()})
	if err != nil {
		t.Fatal(err)
	}
	src.C.Blobs.DeleteGrace = 0
	if err := src.C.Blobs.Delete(ctx, blobOwner, blob.ID, false); err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	if _, err := backup.Export(ctx, src.Migrator, src.C.Backend, testenv.App, dir, "test", "test", src.C.KMS); err != nil {
		t.Fatal(err)
	}
	dst := testenv.EmptyDatabase(t, src.Keyring)
	if _, err := backup.Restore(ctx, dst.Migrator, dst.C.Backend, dir, false, dst.C.KMS); err != nil {
		t.Fatal(err)
	}
	retryOwner := dst.Ctx(t, "engineer@rel.test")
	retryOwner.OpID = owner.OpID
	replay, err := dst.C.Records.Create(ctx, retryOwner, "plain", input)
	if err != nil || replay.ID != original.ID || !replay.Replayed {
		t.Fatalf("restored receipt repeated a create: %+v %v", replay, err)
	}
	var key string
	if err := dst.Migrator.QueryRow(ctx, `SELECT storage_key FROM blobs WHERE app=$1 AND id=$2`, testenv.App, blob.ID).Scan(&key); err != nil {
		t.Fatal(err)
	}
	before, err := dst.C.Backend.Read(ctx, key)
	if err != nil {
		t.Fatal(err)
	}
	_ = before.Close()
	if _, err := dst.C.Worker.RunOnce(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := dst.C.Backend.Read(ctx, key); err == nil {
		t.Fatal("restored deletion intent was lost")
	}
}

func TestSealedRestoreRefusesSourceObjectNamespaceAndSymlinkAliases(t *testing.T) {
	src, ctx := testenv.New(t), context.Background()
	dir := t.TempDir()
	if _, err := backup.Export(ctx, src.Migrator, src.C.Backend, testenv.App, dir, "test", "test", src.C.KMS); err != nil {
		t.Fatal(err)
	}
	dst := testenv.EmptyDatabase(t, src.Keyring)
	backend := &reviewCountingBackend{Backend: src.C.Backend}
	if _, err := backup.Restore(ctx, dst.Migrator, backend, dir, false, dst.C.KMS); err == nil {
		t.Fatal("separate database reused source files")
	}
	if backend.writes != 0 {
		t.Fatal("namespace refusal wrote objects")
	}
	alias := filepath.Join(t.TempDir(), "source-alias")
	if err := os.Symlink(src.BlobDir, alias); err != nil {
		t.Fatal(err)
	}
	linked, err := store.NewLocal(alias)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := backup.Restore(ctx, dst.Migrator, linked, dir, true, dst.C.KMS); err == nil {
		t.Fatal("source directory symlink bypassed refusal")
	}
}
