package service_test

import (
	"context"
	"testing"

	"github.com/paulmalmquist/storage_relspace/internal/admin"
	"github.com/paulmalmquist/storage_relspace/internal/markings"
	"github.com/paulmalmquist/storage_relspace/internal/service"
	"github.com/paulmalmquist/storage_relspace/internal/testenv"
)

func TestManagedAttachmentLifecycle(t *testing.T) {
	e, ctx := testenv.New(t), context.Background()
	notes(t, e)
	owner, member := e.Ctx(t, "engineer@rel.test"), e.Ctx(t, "teammate@rel.test")
	blob := must[*service.BlobMeta](t)(e.C.Blobs.Put(ctx, owner, []byte("fixture"), service.BlobInput{}))
	input := in(`{"tag":"finding"}`)
	input.AttachmentID = &blob.ID
	input.Visibility = "app"
	create := owner
	create.OpID = "finding-and-file-001"
	rec := must[*service.Record](t)(e.C.Records.Create(ctx, create, "notes", input))
	check := func(rec *service.Record, visible bool) {
		t.Helper()
		if (rec.AttachmentID != nil) != visible || visible && *rec.AttachmentID != blob.ID {
			t.Fatalf("link visible=%v, got %v", visible, rec.AttachmentID)
		}
	}
	check(rec, true)
	different := input
	different.AttachmentID = nil
	_, err := e.C.Records.Create(ctx, create, "notes", different)
	wantCode(t, err, "idempotency_key_reused")
	check(must[*service.Record](t)(e.C.Records.Get(ctx, member, "notes", rec.ID)), false)
	ref := service.ResourceRef{Kind: "blob", ID: blob.ID}
	g := must[*service.Grant](t)(e.C.Sharing.AddGrant(ctx, owner, ref, service.GrantInput{Subject: member.Principal.Subject, Role: "viewer"}))
	check(must[*service.Record](t)(e.C.Records.RevisionContent(ctx, member, "notes", rec.ID, 1)), true)
	if err := e.C.Sharing.RemoveGrant(ctx, owner, ref, g.ID); err != nil {
		t.Fatal(err)
	}
	check(must[*service.Record](t)(e.C.Records.RevisionContent(ctx, member, "notes", rec.ID, 1)), false)
	items, _, err := e.C.Records.Query(ctx, member, "notes", nil, 5, "")
	if err != nil || len(items) != 1 {
		t.Fatal(items, err)
	}
	check(items[0], false)
	check(must[*service.Record](t)(e.C.Records.Update(ctx, owner, "notes", rec.ID, in(`{"tag":"same file"}`), 1)), true)
	for _, shred := range []bool{false, true} {
		wantCode(t, e.C.Blobs.Delete(ctx, owner, blob.ID, shred), "conflict")
	}
	operator := &admin.Admin{Pool: e.Migrator, Actor: "admin-cli:test", Stripes: 4}
	wantCode(t, operator.TransferOwner(ctx, testenv.App, "record", rec.ID, member.Principal.Subject), "conflict")
	wantCode(t, operator.TransferOwner(ctx, testenv.App, "blob", blob.ID, member.Principal.Subject), "conflict")
	empty := ""
	detach := in(`{"tag":"detached"}`)
	detach.AttachmentID = &empty
	check(must[*service.Record](t)(e.C.Records.Update(ctx, owner, "notes", rec.ID, detach, 2)), false)
	check(must[*service.Record](t)(e.C.Records.Restore(ctx, owner, "notes", rec.ID, 1, 3)), true)
	v := 4
	if err := e.C.Records.Delete(ctx, owner, "notes", rec.ID, &v, false); err != nil {
		t.Fatal(err)
	}
	if err := e.C.Blobs.Delete(ctx, owner, blob.ID, true); err != nil {
		t.Fatal(err)
	}
	_, err = e.C.Records.Restore(ctx, owner, "notes", rec.ID, 1, 5)
	wantCode(t, err, "not_found")
	check(must[*service.Record](t)(e.C.Records.Create(ctx, create, "notes", input)), false)
}

func TestManagedAttachmentChecksScopeOwnerAndMarking(t *testing.T) {
	e, ctx := testenv.New(t), context.Background()
	notes(t, e)
	owner, mate := e.Ctx(t, "engineer@rel.test"), e.Ctx(t, "teammate@rel.test")
	b := must[*service.BlobMeta](t)(e.C.Blobs.Put(ctx, mate, []byte("visible"), service.BlobInput{Visibility: "app"}))
	input := in(`{"tag":"invalid"}`)
	input.AttachmentID = &b.ID
	_, err := e.C.Records.Create(ctx, owner, "notes", input)
	wantCode(t, err, "not_found")
	cui := markings.MustParse("CUI//SP-EXPT")
	b = must[*service.BlobMeta](t)(e.C.Blobs.Put(ctx, owner, []byte("synthetic"), service.BlobInput{Marking: cui}))
	input.AttachmentID = &b.ID
	_, err = e.C.Records.Create(ctx, owner, "notes", input)
	wantCode(t, err, "validation_failed")
	other := e.CtxIn(t, testenv.Other, "admin@rel.test")
	must[*service.Collection](t)(e.C.Records.CreateCollection(ctx, other, service.CollectionInput{Name: "notes"}))
	foreign := must[*service.BlobMeta](t)(e.C.Blobs.Put(ctx, other, []byte("other app"), service.BlobInput{}))
	input.AttachmentID = &foreign.ID
	_, err = e.C.Records.Create(ctx, e.Ctx(t, "admin@rel.test"), "notes", input)
	wantCode(t, err, "not_found")
	b = must[*service.BlobMeta](t)(e.C.Blobs.Put(ctx, owner, []byte("mine"), service.BlobInput{}))
	input.AttachmentID = &b.ID
	rec := must[*service.Record](t)(e.C.Records.Create(ctx, owner, "notes", input))
	must[*service.Grant](t)(e.C.Sharing.AddGrant(ctx, owner, service.ResourceRef{Kind: "record", Collection: "notes", ID: rec.ID}, service.GrantInput{Subject: mate.Principal.Subject, Role: "editor"}))
	empty := ""
	input.AttachmentID = &empty
	_, err = e.C.Records.Update(ctx, mate, "notes", rec.ID, input, 1)
	wantCode(t, err, "forbidden")
}

func TestLinkRacingBlobShred(t *testing.T) {
	e, ctx := testenv.New(t), context.Background()
	notes(t, e)
	u := e.Ctx(t, "engineer@rel.test")
	for range 6 {
		b := must[*service.BlobMeta](t)(e.C.Blobs.Put(ctx, u, []byte("x"), service.BlobInput{}))
		input := in(`{"tag":"race"}`)
		input.AttachmentID = &b.ID
		start := make(chan struct{})
		saved := make(chan error, 1)
		removed := make(chan error, 1)
		go func() { <-start; _, err := e.C.Records.Create(ctx, u, "notes", input); saved <- err }()
		go func() { <-start; removed <- e.C.Blobs.Delete(ctx, u, b.ID, true) }()
		close(start)
		saveErr, removeErr := <-saved, <-removed
		if saveErr == nil {
			wantCode(t, removeErr, "conflict")
		} else {
			if removeErr != nil {
				t.Fatalf("both failed: %v, %v", saveErr, removeErr)
			}
			wantCode(t, saveErr, "not_found")
		}
	}
}

func TestAttachmentEditReceiptRechecksFileGrant(t *testing.T) {
	e, ctx := testenv.New(t), context.Background()
	notes(t, e)
	u, mate := e.Ctx(t, "engineer@rel.test"), e.Ctx(t, "teammate@rel.test")
	b := must[*service.BlobMeta](t)(e.C.Blobs.Put(ctx, u, []byte("synthetic"), service.BlobInput{}))
	inp := in(`{"tag":"initial"}`)
	inp.AttachmentID = &b.ID
	rec := must[*service.Record](t)(e.C.Records.Create(ctx, u, "notes", inp))
	ref := service.ResourceRef{Kind: "blob", ID: b.ID}
	grant := must[*service.Grant](t)(e.C.Sharing.AddGrant(ctx, u, ref, service.GrantInput{Subject: mate.Principal.Subject, Role: "viewer"}))
	must[*service.Grant](t)(e.C.Sharing.AddGrant(ctx, u, service.ResourceRef{Kind: "record", Collection: "notes", ID: rec.ID}, service.GrantInput{Subject: mate.Principal.Subject, Role: "editor"}))
	mate.OpID = "edit-with-file-grant"
	edit := in(`{"tag":"edited"}`)
	if got := must[*service.Record](t)(e.C.Records.Update(ctx, mate, "notes", rec.ID, edit, 1)); got.AttachmentID == nil {
		t.Fatal("granted file missing")
	}
	if err := e.C.Sharing.RemoveGrant(ctx, u, ref, grant.ID); err != nil {
		t.Fatal(err)
	}
	got := must[*service.Record](t)(e.C.Records.Update(ctx, mate, "notes", rec.ID, edit, 1))
	if !got.Replayed || got.AttachmentID != nil {
		t.Fatalf("replay after file revocation: %+v", got)
	}
}
