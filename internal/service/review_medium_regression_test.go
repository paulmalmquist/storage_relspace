package service_test

import (
	"bytes"
	"context"
	"testing"

	"github.com/paulmalmquist/storage_relspace/internal/service"
	"github.com/paulmalmquist/storage_relspace/internal/testenv"
)

func TestReviewPartReceiptSurvivesCompletionAndRejectsChangedBody(t *testing.T) {
	e, ctx := testenv.New(t), context.Background()
	u := e.Ctx(t, "engineer@rel.test")
	session := must[*service.UploadSession](t)(e.C.Blobs.CreateSession(ctx, u, service.BlobInput{Marking: cuiExpt, DeclaredSize: 1}))
	u.OpID = "part-stable-operation"
	if _, err := e.C.Blobs.PutPart(ctx, u, session.ID, 1, bytes.NewBufferString("a")); err != nil {
		t.Fatal(err)
	}
	if _, err := e.C.Blobs.PutPart(ctx, u, session.ID, 1, bytes.NewBufferString("b")); err == nil {
		t.Fatal("changed body reused operation ID")
	}
	complete := u
	complete.OpID = "complete-stable-operation"
	must[*service.BlobMeta](t)(e.C.Blobs.CompleteSession(ctx, complete, session.ID))
	if _, err := e.C.Blobs.PutPart(ctx, u, session.ID, 1, bytes.NewBufferString("a")); err != nil {
		t.Fatal(err)
	}
	_, body, err := e.C.Blobs.ReadAll(ctx, u, session.ID)
	if err != nil || string(body) != "a" {
		t.Fatalf("replay changed stream: %q %v", body, err)
	}
	var n int
	if err := e.Migrator.QueryRow(ctx, `SELECT count(*) FROM operation_receipts WHERE app=$1 AND op_id=$2 AND status='succeeded'`, testenv.App, u.OpID).Scan(&n); err != nil || n != 1 {
		t.Fatalf("receipt count %d: %v", n, err)
	}
}

func TestReviewSharingReceiptDoesNotRepeatAnOldChange(t *testing.T) {
	e, ctx := testenv.New(t), context.Background()
	notes(t, e)
	owner := e.Ctx(t, "engineer@rel.test")
	rec := must[*service.Record](t)(e.C.Records.Create(ctx, owner, "notes", service.RecordInput{Data: map[string]any{"x": 1}}))
	ref := service.ResourceRef{Kind: "record", Collection: "notes", ID: rec.ID}
	owner.OpID = "visibility-app-operation"
	if err := e.C.Sharing.SetVisibility(ctx, owner, ref, "app", ""); err != nil {
		t.Fatal(err)
	}
	later := owner
	later.OpID = "visibility-private-operation"
	if err := e.C.Sharing.SetVisibility(ctx, later, ref, "private", ""); err != nil {
		t.Fatal(err)
	}
	if err := e.C.Sharing.SetVisibility(ctx, owner, ref, "app", ""); err != nil {
		t.Fatal(err)
	}
	_, err := e.C.Records.Get(ctx, e.Ctx(t, "teammate@rel.test"), "notes", rec.ID)
	wantCode(t, err, "not_found")
}

func TestReviewReceiptUsesRetiredFingerprintKey(t *testing.T) {
	e, ctx := testenv.New(t), context.Background()
	notes(t, e)
	u := e.Ctx(t, "engineer@rel.test")
	u.OpID = "retired-fingerprint-operation"
	in := service.RecordInput{Data: map[string]any{"value": "saved"}}
	rec := must[*service.Record](t)(e.C.Records.Create(ctx, u, "notes", in))
	e.Admin(t, `UPDATE data_keys SET retired_at=now() WHERE app=$1 AND purpose='receipt'`, testenv.App)
	other := u
	other.OpID = "new-fingerprint-operation"
	must[*service.Record](t)(e.C.Records.Create(ctx, other, "notes", in))
	retry := must[*service.Record](t)(e.C.Records.Create(ctx, u, "notes", in))
	if retry.ID != rec.ID || !retry.Replayed {
		t.Fatalf("wrong replay: %+v", retry)
	}
}
