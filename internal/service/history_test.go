package service_test

import (
	"context"
	"testing"

	"github.com/paulmalmquist/storage_relspace/internal/service"
	"github.com/paulmalmquist/storage_relspace/internal/testenv"
)

func TestHistoryAndUndo(t *testing.T) {
	env, ctx := testenv.New(t), context.Background()
	ncr(t, env)
	eng := env.Ctx(t, "engineer@rel.test")
	r := must[*service.Record](t)(env.C.Records.Create(ctx, eng, "ncr", in(`{"part_number":"A","status":"open"}`)))
	must[*service.Record](t)(env.C.Records.Update(ctx, eng, "ncr", r.ID, in(`{"part_number":"A","status":"closed","defect":"oops"}`), 1))
	revs, _, err := env.C.Records.History(ctx, eng, "ncr", r.ID, 0, 0)
	if err != nil || len(revs) != 2 || revs[0].Version != 2 || revs[1].Op != "create" {
		t.Fatalf("history: %v %+v", err, revs)
	}
	old := must[*service.Record](t)(env.C.Records.RevisionContent(ctx, eng, "ncr", r.ID, 1))
	if old.Data["status"] != "open" {
		t.Fatalf("revision 1: %v", old.Data)
	}
	// Undo: restore version 1 as version 3 (compare-and-swap on the current version).
	_, err = env.C.Records.Restore(ctx, eng, "ncr", r.ID, 1, 1)
	wantCode(t, err, "precondition_failed")
	undone := must[*service.Record](t)(env.C.Records.Restore(ctx, eng, "ncr", r.ID, 1, 2))
	if undone.Version != 3 || undone.Data["status"] != "open" || undone.Data["defect"] != nil {
		t.Fatalf("restore: %+v", undone)
	}
	revs, _, _ = env.C.Records.History(ctx, eng, "ncr", r.ID, 0, 0)
	if len(revs) != 3 || revs[0].Op != "restore" {
		t.Fatalf("history after restore: %+v", revs)
	}
	// Restoring never lowers the marking.
	must[*service.Record](t)(env.C.Records.Update(ctx, eng, "ncr", r.ID, service.RecordInput{Data: doc(`{"part_number":"A","status":"open"}`), Marking: &expt}, 3))
	back := must[*service.Record](t)(env.C.Records.Restore(ctx, eng, "ncr", r.ID, 1, 4))
	if !back.Marking.Equal(expt) {
		t.Fatalf("restore lowered the marking to %s", back.Marking.Banner())
	}
}

func TestDeletedRecordsAreProtected(t *testing.T) {
	env, ctx := testenv.New(t), context.Background()
	ncr(t, env)
	eng, mate := env.Ctx(t, "engineer@rel.test"), env.Ctx(t, "teammate@rel.test")
	r := must[*service.Record](t)(env.C.Records.Create(ctx, eng, "ncr", shared(`{"part_number":"A","status":"open"}`)))
	if _, _, err := env.C.Records.History(ctx, mate, "ncr", r.ID, 0, 0); err != nil {
		t.Fatalf("reader cannot see live history: %v", err)
	}
	one := 1
	if err := env.C.Records.Delete(ctx, eng, "ncr", r.ID, &one, false); err != nil {
		t.Fatal(err)
	}
	_, _, err := env.C.Records.History(ctx, mate, "ncr", r.ID, 0, 0)
	wantCode(t, err, "not_found")
	_, err = env.C.Records.RevisionContent(ctx, mate, "ncr", r.ID, 1)
	wantCode(t, err, "not_found")
	revs, _, err := env.C.Records.History(ctx, eng, "ncr", r.ID, 0, 0)
	if err != nil || revs[0].Op != "delete" {
		t.Fatalf("owner history: %v %+v", err, revs)
	}
	back := must[*service.Record](t)(env.C.Records.Restore(ctx, eng, "ncr", r.ID, 1, 2))
	if back.Deleted || back.Version != 3 {
		t.Fatalf("undelete: %+v", back)
	}
	if _, err := env.C.Records.Get(ctx, mate, "ncr", r.ID); err != nil {
		t.Fatalf("undeleted record not visible: %v", err)
	}
}

func TestHistoryAuthorizedPerRevisionMarking(t *testing.T) {
	env, ctx := testenv.New(t), context.Background()
	ncr(t, env)
	eng := env.Ctx(t, "engineer@rel.test")
	r := must[*service.Record](t)(env.C.Records.Create(ctx, eng, "ncr", service.RecordInput{Data: doc(`{"part_number":"A","status":"open"}`),
		Marking: &expt, Visibility: "app"}))
	must[*service.Record](t)(env.C.Records.Update(ctx, eng, "ncr", r.ID, service.RecordInput{Data: doc(`{"part_number":"A","status":"closed"}`),
		Marking: &cuiExpt}, 1))
	foreign := env.Ctx(t, "foreign@rel.test") // may see CUI//SP-EXPT? no: SP-EXPT is export controlled
	_, _, err := env.C.Records.History(ctx, foreign, "ncr", r.ID, 0, 0)
	wantCode(t, err, "not_found")
	agent := env.Ctx(t, "agent:assistant")
	revs, _, err := env.C.Records.History(ctx, agent, "ncr", r.ID, 0, 0)
	if err != nil || len(revs) != 2 {
		t.Fatalf("agent history: %v", err)
	}
	_, err = env.C.Records.RevisionContent(ctx, agent, "ncr", r.ID, 1)
	wantCode(t, err, "content_withheld")
}

func TestHistoryRetention(t *testing.T) {
	env, ctx := testenv.New(t), context.Background()
	if _, err := env.C.Records.CreateCollection(ctx, env.Ctx(t, "admin@rel.test"),
		service.CollectionInput{Name: "short", Marking: cuiExpt, HistoryLimit: 2}); err != nil {
		t.Fatal(err)
	}
	eng := env.Ctx(t, "engineer@rel.test")
	r := must[*service.Record](t)(env.C.Records.Create(ctx, eng, "short", in(`{"n":0}`)))
	for v := 1; v <= 4; v++ {
		must[*service.Record](t)(env.C.Records.Update(ctx, eng, "short", r.ID, in(`{"n":1}`), v))
	}
	stats, err := env.C.Worker.RunOnce(ctx)
	if err != nil || stats.RevisionsPruned != 3 {
		t.Fatalf("prune: %v %+v", err, stats)
	}
	revs, _, _ := env.C.Records.History(ctx, eng, "short", r.ID, 0, 0)
	if len(revs) != 2 || revs[1].Version != 4 {
		t.Fatalf("kept %+v", revs)
	}
	_, err = env.C.Records.Restore(ctx, eng, "short", r.ID, 1, 5)
	wantCode(t, err, "not_found")
}
