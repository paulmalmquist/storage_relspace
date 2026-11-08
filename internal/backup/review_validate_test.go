package backup_test

import (
	"bytes"
	"context"
	"testing"

	"github.com/paulmalmquist/storage_relspace/internal/backup"
	"github.com/paulmalmquist/storage_relspace/internal/markings"
	"github.com/paulmalmquist/storage_relspace/internal/service"
	"github.com/paulmalmquist/storage_relspace/internal/testenv"
)

func TestReviewValidateRejectsForeignObjectKey(t *testing.T) {
	ctx, src := context.Background(), testenv.New(t)
	if _, err := src.C.Blobs.CreateSession(ctx, src.Ctx(t, "engineer@rel.test"), service.BlobInput{Marking: markings.None(), DeclaredSize: 1}); err != nil {
		t.Fatal(err)
	}
	dir := reviewExport(t, src)
	reviewRewriteTable(t, dir, "blobs", func(raw []byte) []byte {
		return bytes.ReplaceAll(raw, []byte("apps/acme/test/"), []byte("apps/rival/test/"))
	})
	_, rep, err := backup.Validate(dir)
	if err == nil && rep.OK() {
		t.Fatal("validator accepted another app's object prefix")
	}
}
