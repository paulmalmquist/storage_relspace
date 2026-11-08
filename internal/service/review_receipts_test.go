package service_test

import (
	"context"
	"testing"

	"github.com/paulmalmquist/storage_relspace/internal/service"
	"github.com/paulmalmquist/storage_relspace/internal/testenv"
)

func TestReviewRetryCannotReadDeletedRecord(t *testing.T) {
	env, ctx := testenv.New(t), context.Background()
	ncr(t, env)
	owner, editor := env.Ctx(t, "admin@rel.test"), env.Ctx(t, "engineer@rel.test")
	r := must[*service.Record](t)(env.C.Records.Create(ctx, owner, "ncr", shared(`{"part_number":"A","status":"open"}`)))
	editor.OpID = "review-update-0001"
	changed := must[*service.Record](t)(env.C.Records.Update(ctx, editor, "ncr", r.ID, in(`{"part_number":"A","status":"closed"}`), 1))
	if err := env.C.Records.Delete(ctx, owner, "ncr", r.ID, &changed.Version, false); err != nil {
		t.Fatal(err)
	}
	_, err := env.C.Records.RevisionContent(ctx, editor, "ncr", r.ID, 2)
	wantCode(t, err, "not_found")
	got, err := env.C.Records.Update(ctx, editor, "ncr", r.ID, in(`{"part_number":"A","status":"closed"}`), 1)
	if err == nil {
		t.Fatalf("retry returned deleted content that history refuses: %+v", got)
	}
	wantCode(t, err, "not_found")
}

func TestReviewOperationStatusRechecksResourceAccess(t *testing.T) {
	env, ctx := testenv.New(t), context.Background()
	ncr(t, env)
	owner, editor := env.Ctx(t, "admin@rel.test"), env.Ctx(t, "engineer@rel.test")
	r := must[*service.Record](t)(env.C.Records.Create(ctx, owner, "ncr", shared(`{"part_number":"A","status":"open"}`)))
	editor.OpID = "review-update-0002"
	must[*service.Record](t)(env.C.Records.Update(ctx, editor, "ncr", r.ID, in(`{"part_number":"A","status":"closed"}`), 1))
	if err := env.C.Sharing.SetVisibility(ctx, owner, service.ResourceRef{Kind: "record", Collection: "ncr", ID: r.ID}, "private", ""); err != nil {
		t.Fatal(err)
	}
	_, err := env.C.Records.Get(ctx, editor, "ncr", r.ID)
	wantCode(t, err, "not_found")
	rc, err := env.C.Operation(ctx, editor, editor.OpID)
	if err == nil {
		t.Fatalf("receipt exposes a now-private resource: %+v", rc)
	}
	wantCode(t, err, "not_found")
}
