package backup_test

import (
	"bytes"
	"context"
	"strings"
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

func TestValidateRejectsDanglingManagedAttachment(t *testing.T) {
	src, ctx := testenv.New(t), context.Background()
	u := src.Ctx(t, "admin@rel.test")
	if _, err := src.C.Records.CreateCollection(ctx, u, service.CollectionInput{Name: "evidence", Marking: markings.MustParse("CUI//SP-EXPT")}); err != nil {
		t.Fatal(err)
	}
	b, err := src.C.Blobs.Put(ctx, u, []byte("example"), service.BlobInput{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := src.C.Records.Create(ctx, u, "evidence", service.RecordInput{AttachmentID: &b.ID, Data: map[string]any{"state": "ok"}}); err != nil {
		t.Fatal(err)
	}
	dir := reviewExport(t, src)
	reviewRewriteTable(t, dir, "records", func(raw []byte) []byte { return bytes.ReplaceAll(raw, []byte(b.ID), []byte("blb_missing")) })
	_, report, err := backup.Validate(dir)
	if err != nil {
		t.Fatal(err)
	}
	if report.OK() || !strings.Contains(strings.Join(report.Problems, " "), "attachment references") {
		t.Fatalf("accepted invalid link: %+v", report)
	}
}
