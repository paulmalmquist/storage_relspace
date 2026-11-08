package service_test

import (
	"context"
	"github.com/paulmalmquist/storage_relspace/internal/service"
	"github.com/paulmalmquist/storage_relspace/internal/testenv"
	"testing"
)

func TestReviewShareOnlyGranteeCanChangeVisibility(t *testing.T) {
	env, ctx := testenv.New(t), context.Background()
	notes(t, env)
	owner, mate := env.Ctx(t, "engineer@rel.test"), env.Ctx(t, "teammate@rel.test")
	rec := must[*service.Record](t)(env.C.Records.Create(ctx, owner, "notes", in(`{"tag":"x"}`)))
	ref := service.ResourceRef{Kind: "record", Collection: "notes", ID: rec.ID}
	must[*service.Grant](t)(env.C.Sharing.AddGrant(ctx, owner, ref, service.GrantInput{Subject: mate.Principal.Subject, Role: "viewer", CanShare: true}))
	if err := env.C.Sharing.SetVisibility(ctx, mate, ref, "app", ""); err != nil {
		t.Fatalf("share permission refused: %v", err)
	}
	got := must[*service.Record](t)(env.C.Records.Get(ctx, owner, "notes", rec.ID))
	// A share-only grant must not become edit or delegation permission.
	_, err := env.C.Records.Update(ctx, mate, "notes", rec.ID, in(`{"tag":"changed"}`), 1)
	wantCode(t, err, "forbidden")
	_, err = env.C.Sharing.AddGrant(ctx, mate, ref, service.GrantInput{Subject: "intern@rel.test", Role: "viewer", CanShare: true})
	wantCode(t, err, "forbidden")
	if got.Visibility != "app" {
		t.Fatalf("SetVisibility returned success but left visibility=%s", got.Visibility)
	}
}

func TestReviewExistingGrantCanBeChanged(t *testing.T) {
	env, ctx := testenv.New(t), context.Background()
	notes(t, env)
	owner := env.Ctx(t, "engineer@rel.test")
	rec := must[*service.Record](t)(env.C.Records.Create(ctx, owner, "notes", in(`{"tag":"x"}`)))
	ref := service.ResourceRef{Kind: "record", Collection: "notes", ID: rec.ID}
	g := must[*service.Grant](t)(env.C.Sharing.AddGrant(ctx, owner, ref, service.GrantInput{Subject: "teammate@rel.test", Role: "viewer"}))
	updated, err := env.C.Sharing.AddGrant(ctx, owner, ref, service.GrantInput{Subject: "teammate@rel.test", Role: "editor"})
	if err != nil {
		t.Fatalf("owner cannot update existing grant %s: %v", g.ID, err)
	}
	if updated.ID != g.ID || updated.Role != "editor" {
		t.Fatalf("wrong updated grant: %+v", updated)
	}
}

func TestReviewUsageDoesNotCountHiddenResources(t *testing.T) {
	env, ctx := testenv.New(t), context.Background()
	notes(t, env)
	owner, viewer := env.Ctx(t, "engineer@rel.test"), env.Ctx(t, "teammate@rel.test")
	before := must[*service.AppUsage](t)(env.C.Sharing.Usage(ctx, viewer))
	must[*service.Record](t)(env.C.Records.Create(ctx, owner, "notes", in(`{"tag":"private"}`)))
	rows, _, err := env.C.Records.Query(ctx, viewer, "notes", nil, 200, "")
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 0 {
		t.Fatal("test row should be hidden")
	}
	after := must[*service.AppUsage](t)(env.C.Sharing.Usage(ctx, viewer))
	if after.Records != before.Records || after.RecordBytes != before.RecordBytes {
		t.Fatalf("hidden write changed public usage from %+v to %+v", before, after)
	}
}

func TestReviewMigrationDoesNotDisclosePrivateRecordIDs(t *testing.T) {
	env, ctx := testenv.New(t), context.Background()
	notes(t, env)
	owner, adm, viewer := env.Ctx(t, "engineer@rel.test"), env.Ctx(t, "admin@rel.test"), env.Ctx(t, "teammate@rel.test")
	rec := must[*service.Record](t)(env.C.Records.Create(ctx, owner, "notes", in(`{"tag":"private"}`)))
	ch := must[*service.ContractChange](t)(env.C.Records.ChangeContract(ctx, adm, "notes", service.ContractInput{ExpectedVersion: 1, JSONSchema: map[string]any{"type": "object", "required": []any{"missing"}}}))
	if _, err := env.C.Worker.RunOnce(ctx); err != nil {
		t.Fatal(err)
	}
	m, err := env.C.Records.GetMigration(ctx, viewer, "notes", ch.Migration.ID)
	if err != nil {
		return
	} // restricting operational details is a valid solution
	for _, failure := range m.Failures {
		if failure.RecordID == rec.ID {
			t.Fatalf("collection reader learned private record ID from migration: %+v", m)
		}
	}
}

func TestReviewUploadStatusRechecksClearance(t *testing.T) {
	env, ctx := testenv.New(t), context.Background()
	user := env.Ctx(t, "engineer@rel.test")
	sess := must[*service.UploadSession](t)(env.C.Blobs.CreateSession(ctx, user, service.BlobInput{Marking: cuiExpt, DeclaredSize: 1}))
	env.Admin(t, `UPDATE principals SET cui_access=false WHERE subject=$1`, user.Principal.Subject)
	user = env.Ctx(t, user.Principal.Subject)
	got, err := env.C.Blobs.Session(ctx, user, sess.ID)
	if err == nil {
		t.Fatalf("uncleared uploader can still read CUI upload status: %+v", got)
	}
	wantCode(t, err, "not_found")
}
