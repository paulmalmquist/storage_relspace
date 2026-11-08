//go:build strongbox_review_repro

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

func TestReviewExportContainsNoPlaintextRecordData(t *testing.T) {
	src, ctx := testenv.New(t), context.Background()
	user := src.Ctx(t, "admin@rel.test")
	if _, err := src.C.Records.CreateCollection(ctx, user, service.CollectionInput{Name: "plain", Marking: markings.None(), IndexedFields: []string{"tag"}}); err != nil {
		t.Fatal(err)
	}
	marker := "private-user-state-export-marker"
	if _, err := src.C.Records.Create(ctx, user, "plain", service.RecordInput{Data: map[string]any{"tag": marker}}); err != nil {
		t.Fatal(err)
	}
	dir := reviewExport(t, src)
	for _, name := range []string{"records", "record_revisions", "record_index"} {
		raw, err := os.ReadFile(filepath.Join(dir, "tables", name+".ndjson"))
		if err != nil {
			t.Fatal(err)
		}
		if bytes.Contains(raw, []byte(marker)) {
			t.Errorf("ciphertext-only export contains private plaintext in %s", name)
		}
	}
}

func TestReviewOfflineValidationRequiresCompletePartList(t *testing.T) {
	src, ctx := testenv.New(t), context.Background()
	user := src.Ctx(t, "engineer@rel.test")
	session, err := src.C.Blobs.CreateSession(ctx, user, service.BlobInput{Marking: markings.None(), DeclaredSize: 1})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := src.C.Blobs.PutPart(ctx, user, session.ID, 1, bytes.NewReader([]byte("a"))); err != nil {
		t.Fatal(err)
	}
	if _, err := src.C.Blobs.CompleteSession(ctx, user, session.ID); err != nil {
		t.Fatal(err)
	}
	dir := reviewExport(t, src)
	reviewRewriteTable(t, dir, "blob_parts", func([]byte) []byte { return nil })
	// Remove the no-longer-referenced object inventory as well, recalculating its digest.
	raw, err := os.ReadFile(filepath.Join(dir, "objects.ndjson"))
	if err != nil {
		t.Fatal(err)
	}
	_ = raw
	if err := os.WriteFile(filepath.Join(dir, "objects.ndjson"), nil, 0600); err != nil {
		t.Fatal(err)
	}
	reviewManifest(t, dir, func(m *backup.Manifest) {
		m.Objects.Count = 0
		m.Objects.Bytes = 0
		m.Objects.SHA256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
	})
	_, report, err := backup.Validate(dir)
	if err == nil && report.OK() {
		t.Fatal("offline validation accepted an active multipart blob with zero parts")
	}
}

func TestReviewRestoreRefusesSameDatabaseAcrossSchemas(t *testing.T) {
	src, ctx := testenv.New(t), context.Background()
	dst := testenv.Empty(t, src.Keyring) // another schema of the source database
	dir := reviewExport(t, src)
	if _, err := backup.Restore(ctx, dst.Migrator, dst.C.Backend, dir, true); err == nil {
		t.Fatal("restore accepted the source database under a different schema")
	}
}
