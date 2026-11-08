package service_test

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/paulmalmquist/storage_relspace/internal/service"
	"github.com/paulmalmquist/storage_relspace/internal/testenv"
)

func batchUpdate(id string, v int, value string) service.BatchOperation {
	input := in(`{"tag":"` + value + `"}`)
	return service.BatchOperation{Type: "update", Collection: "notes", ID: id, ExpectedVersion: v, Record: &input}
}
func TestBatchCommitsOnceAndRechecksEveryResource(t *testing.T) {
	e, ctx := testenv.New(t), context.Background()
	notes(t, e)
	owner, mate := e.Ctx(t, "engineer@rel.test"), e.Ctx(t, "teammate@rel.test")
	one := must[*service.Record](t)(e.C.Records.Create(ctx, owner, "notes", in(`{"tag":"one"}`)))
	two := must[*service.Record](t)(e.C.Records.Create(ctx, owner, "notes", in(`{"tag":"two"}`)))
	for _, id := range []string{one.ID, two.ID} {
		must[*service.Grant](t)(e.C.Sharing.AddGrant(ctx, owner, service.ResourceRef{Kind: "record", Collection: "notes", ID: id}, service.GrantInput{Subject: mate.Principal.Subject, Role: "editor"}))
	}
	mate.OpID = "batch-edit-one-operation"
	ops := []service.BatchOperation{batchUpdate(one.ID, 1, "first"), batchUpdate(two.ID, 1, "second")}
	result := must[*service.BatchResult](t)(e.C.Records.Batch(ctx, mate, ops))
	retry := must[*service.BatchResult](t)(e.C.Records.Batch(ctx, mate, ops))
	if result.Replayed || !retry.Replayed || retry.Operations[0].Version != 2 || retry.Operations[1].Version != 2 {
		t.Fatalf("incorrect receipt: %+v %+v", result, retry)
	}
	var receipts int
	if err := e.Migrator.QueryRow(ctx, `SELECT count(*) FROM operation_receipts WHERE app=$1 AND subject=$2`, testenv.App, mate.Principal.Subject).Scan(&receipts); err != nil || receipts != 1 {
		t.Fatalf("wanted one parent receipt, got %d %v", receipts, err)
	}
	attempt := mate
	attempt.OpID = "batch-editor-delete-attempt"
	_, err := e.C.Records.Batch(ctx, attempt, []service.BatchOperation{batchUpdate(one.ID, 2, "should-roll-back"), {Type: "delete", Collection: "notes", ID: two.ID, ExpectedVersion: 2}})
	wantCode(t, err, "forbidden")
	original := must[*service.Record](t)(e.C.Records.Get(ctx, mate, "notes", one.ID))
	if original.Version != 2 {
		t.Fatal("editing escalated to management or partially committed")
	}
	grants := must[[]service.Grant](t)(e.C.Sharing.Grants(ctx, owner, service.ResourceRef{Kind: "record", Collection: "notes", ID: two.ID}))
	if err := e.C.Sharing.RemoveGrant(ctx, owner, service.ResourceRef{Kind: "record", Collection: "notes", ID: two.ID}, grants[0].ID); err != nil {
		t.Fatal(err)
	}
	_, err = e.C.Records.Batch(ctx, mate, ops)
	wantCode(t, err, "not_found")
	_, err = e.C.Operation(ctx, mate, mate.OpID)
	wantCode(t, err, "not_found")
}
func TestBatchConflictRollsBackEarlierWritesAuditAndReceipt(t *testing.T) {
	e, ctx := testenv.New(t), context.Background()
	notes(t, e)
	u := e.Ctx(t, "engineer@rel.test")
	one := must[*service.Record](t)(e.C.Records.Create(ctx, u, "notes", in(`{"tag":"one"}`)))
	two := must[*service.Record](t)(e.C.Records.Create(ctx, u, "notes", in(`{"tag":"two"}`)))

	u.OpID = "batch-stale-operation"
	_, err := e.C.Records.Batch(ctx, u, []service.BatchOperation{batchUpdate(one.ID, 1, "new"), batchUpdate(two.ID, 2, "stale")})
	wantCode(t, err, "precondition_failed")
	got := must[*service.Record](t)(e.C.Records.Get(ctx, u, "notes", one.ID))
	if got.Version != 1 || got.Data["tag"] != "one" {
		t.Fatalf("partial save %+v", got)
	}
	var n int
	if err := e.Migrator.QueryRow(ctx, `SELECT count(*) FROM operation_receipts WHERE app=$1 AND op_id=$2`, testenv.App, u.OpID).Scan(&n); err != nil || n != 0 {
		t.Fatalf("failed receipt persisted: %d %v", n, err)
	}
	// Exclude the explicit read above; successful mutation events must all have rolled back.
	if err := e.Migrator.QueryRow(ctx, `SELECT count(*) FROM audit_events WHERE app=$1 AND action='record.update'`, testenv.App).Scan(&n); err != nil || n != 0 {
		t.Fatalf("partial audit events persisted: %d %v", n, err)
	}
}
func TestBatchQuotaFailureRollsBackAllCreates(t *testing.T) {
	e, ctx := testenv.New(t), context.Background()
	notes(t, e)
	e.Admin(t, `INSERT INTO app_quotas(app,max_records,updated_by) VALUES($1,1,'test') ON CONFLICT(app) DO UPDATE SET max_records=1`, testenv.App)
	u := e.Ctx(t, "engineer@rel.test")
	u.OpID = "batch-quota-operation"
	input := in(`{"tag":"created"}`)
	_, err := e.C.Records.Batch(ctx, u, []service.BatchOperation{{Type: "create", Collection: "notes", Record: &input}, {Type: "create", Collection: "notes", Record: &input}})
	wantCode(t, err, "quota_exceeded")
	var n int
	if err := e.Migrator.QueryRow(ctx, `SELECT count(*) FROM records WHERE app=$1`, testenv.App).Scan(&n); err != nil || n != 0 {
		t.Fatalf("partial creates %d %v", n, err)
	}
}
func TestBatchHistoryPinsAndMetadataOnlyReplay(t *testing.T) {
	e, ctx := testenv.New(t), context.Background()
	notes(t, e)
	u := e.Ctx(t, "engineer@rel.test")
	e.Admin(t, `UPDATE collections SET history_limit=1 WHERE app=$1 AND name='notes'`, testenv.App)
	record := must[*service.Record](t)(e.C.Records.Create(ctx, u, "notes", in(`{"tag":"v1"}`)))
	u.OpID = "batch-pinned-operation"
	ops := []service.BatchOperation{batchUpdate(record.ID, 1, "v2")}
	must[*service.BatchResult](t)(e.C.Records.Batch(ctx, u, ops))
	later := u
	later.OpID = ""
	must[*service.Record](t)(e.C.Records.Update(ctx, later, "notes", record.ID, in(`{"tag":"v3"}`), 2))
	retry := must[*service.BatchResult](t)(e.C.Records.Batch(ctx, u, ops))
	if retry.Operations[0].Version != 2 {
		t.Fatalf("wrong original outcome %+v", retry)
	}
	old := must[*service.Record](t)(e.C.Records.RevisionContent(ctx, u, "notes", record.ID, 2))
	if old.Data["tag"] != "v2" {
		t.Fatalf("pinned revision lost %+v", old)
	}
}
func TestBatchRejectsUnboundedAndDuplicateTargets(t *testing.T) {
	e, ctx := testenv.New(t), context.Background()
	u := e.Ctx(t, "engineer@rel.test")
	u.OpID = "batch-invalid-operation"
	cases := [][]service.BatchOperation{
		nil,
		make([]service.BatchOperation, service.MaxBatchOperations+1),
		{batchUpdate("rec_one", 1, "a"), batchUpdate("rec_one", 1, "b")},
		{{Type: "delete", Collection: "notes", ID: "rec_one"}},
		{{Type: "create", Collection: "notes", Record: &service.RecordInput{Data: map[string]any{"large": strings.Repeat("x", service.MaxBatchBytes)}}}},
	}
	for _, ops := range cases {
		if _, err := e.C.Records.Batch(ctx, u, ops); err == nil {
			t.Fatal("invalid batch accepted")
		}
	}
}

func TestBatchDeleteRestoreAndCrossAppIsolation(t *testing.T) {
	e, ctx := testenv.New(t), context.Background()
	notes(t, e)
	u := e.Ctx(t, "engineer@rel.test")
	own := must[*service.Record](t)(e.C.Records.Create(ctx, u, "notes", in(`{"tag":"one"}`)))
	other := e.CtxIn(t, testenv.Other, "admin@rel.test")
	must[*service.Collection](t)(e.C.Records.CreateCollection(ctx, other, service.CollectionInput{Name: "notes", Marking: cuiExpt}))
	foreign := must[*service.Record](t)(e.C.Records.Create(ctx, other, "notes", in(`{"tag":"foreign"}`)))
	u.OpID = "batch-cross-app-operation"
	_, err := e.C.Records.Batch(ctx, u, []service.BatchOperation{batchUpdate(own.ID, 1, "changed"), batchUpdate(foreign.ID, 1, "attack")})
	wantCode(t, err, "not_found")
	got := must[*service.Record](t)(e.C.Records.Get(ctx, u, "notes", own.ID))
	if got.Version != 1 {
		t.Fatal("foreign ID caused a partial write")
	}
	u.OpID = "batch-delete-operation"
	deleted := must[*service.BatchResult](t)(e.C.Records.Batch(ctx, u, []service.BatchOperation{{Type: "delete", Collection: "notes", ID: own.ID, ExpectedVersion: 1}}))
	if deleted.Operations[0].Version != 2 {
		t.Fatal("wrong delete version")
	}
	restore := u
	restore.OpID = "batch-restore-operation"
	recovered := must[*service.BatchResult](t)(e.C.Records.Batch(ctx, restore, []service.BatchOperation{{Type: "restore", Collection: "notes", ID: own.ID, ExpectedVersion: 2, RestoreVersion: 1}}))
	if recovered.Operations[0].Version != 3 {
		t.Fatal("restore did not create a new version")
	}
	must[*service.BatchResult](t)(e.C.Records.Batch(ctx, u, []service.BatchOperation{{Type: "delete", Collection: "notes", ID: own.ID, ExpectedVersion: 1}}))
	got = must[*service.Record](t)(e.C.Records.Get(ctx, u, "notes", own.ID))
	if got.Version != 3 {
		t.Fatal("old delete retry deleted a restored record")
	}
}
func TestBatchUniquenessFailureIsPrivateAndAtomic(t *testing.T) {
	e, ctx := testenv.New(t), context.Background()
	must[*service.Collection](t)(e.C.Records.CreateCollection(ctx, e.Ctx(t, "admin@rel.test"), service.CollectionInput{Name: "unique", Marking: cuiExpt, IndexedFields: []string{"tag"}, UniqueFields: []string{"tag"}}))
	hidden := must[*service.Record](t)(e.C.Records.Create(ctx, e.Ctx(t, "engineer@rel.test"), "unique", in(`{"tag":"occupied"}`)))
	mate := e.Ctx(t, "teammate@rel.test")
	mate.OpID = "batch-unique-operation"
	one, two := in(`{"tag":"free"}`), in(`{"tag":"occupied"}`)
	_, err := e.C.Records.Batch(ctx, mate, []service.BatchOperation{{Type: "create", Collection: "unique", Record: &one}, {Type: "create", Collection: "unique", Record: &two}})
	wantCode(t, err, "unique_violation")
	if strings.Contains(err.Error(), hidden.ID) {
		t.Fatal("unique error disclosed hidden record")
	}
	var n int
	if err := e.Migrator.QueryRow(ctx, `SELECT count(*) FROM records WHERE app=$1 AND owner=$2`, testenv.App, mate.Principal.Subject).Scan(&n); err != nil || n != 0 {
		t.Fatalf("unique failure partially committed %d %v", n, err)
	}
}
func TestConcurrentBatchesHaveOneWinner(t *testing.T) {
	e, ctx := testenv.New(t), context.Background()
	notes(t, e)
	u := e.Ctx(t, "engineer@rel.test")
	one := must[*service.Record](t)(e.C.Records.Create(ctx, u, "notes", in(`{"tag":"one"}`)))
	two := must[*service.Record](t)(e.C.Records.Create(ctx, u, "notes", in(`{"tag":"two"}`)))
	done := make(chan error, 2)
	start := make(chan struct{})
	for i := 0; i < 2; i++ {
		go func(i int) {
			c := u
			c.OpID = fmt.Sprintf("concurrent-batch-operation-%d", i)
			ops := []service.BatchOperation{batchUpdate(one.ID, 1, fmt.Sprint(i)), batchUpdate(two.ID, 1, fmt.Sprint(i))}
			if i == 1 {
				ops[0], ops[1] = ops[1], ops[0]
			}
			<-start
			_, err := e.C.Records.Batch(ctx, c, ops)
			done <- err
		}(i)
	}
	close(start)
	wins := 0
	for i := 0; i < 2; i++ {
		err := <-done
		if err == nil {
			wins++
		} else {
			wantCode(t, err, "precondition_failed")
		}
	}
	if wins != 1 {
		t.Fatalf("batch winners %d", wins)
	}
	a := must[*service.Record](t)(e.C.Records.Get(ctx, u, "notes", one.ID))
	b := must[*service.Record](t)(e.C.Records.Get(ctx, u, "notes", two.ID))
	if a.Version != 2 || b.Version != 2 || a.Data["tag"] != b.Data["tag"] {
		t.Fatalf("mixed batch outcomes %+v %+v", a, b)
	}
}

func TestBatchWritersSatisfyPendingContract(t *testing.T) {
	e, ctx := testenv.New(t), context.Background()
	notes(t, e)
	u := e.Ctx(t, "engineer@rel.test")
	one := must[*service.Record](t)(e.C.Records.Create(ctx, u, "notes", in(`{"tag":"one"}`)))
	two := must[*service.Record](t)(e.C.Records.Create(ctx, u, "notes", in(`{"tag":"two"}`)))
	must[*service.ContractChange](t)(e.C.Records.ChangeContract(ctx, e.Ctx(t, "admin@rel.test"), "notes", service.ContractInput{ExpectedVersion: 1, JSONSchema: map[string]any{"type": "object", "required": []string{"state"}}}))
	valid, invalid := in(`{"tag":"one","state":"open"}`), in(`{"tag":"two"}`)
	u.OpID = "batch-staged-contract-operation"
	_, err := e.C.Records.Batch(ctx, u, []service.BatchOperation{{Type: "update", Collection: "notes", ID: one.ID, ExpectedVersion: 1, Record: &valid}, {Type: "update", Collection: "notes", ID: two.ID, ExpectedVersion: 1, Record: &invalid}})
	wantCode(t, err, "validation_failed")
	got := must[*service.Record](t)(e.C.Records.Get(ctx, u, "notes", one.ID))
	if got.Version != 1 {
		t.Fatal("pending-schema failure partially committed batch")
	}
}

func TestBatchAuditFailureRollsBackEverything(t *testing.T) {
	e, ctx := testenv.New(t), context.Background()
	notes(t, e)
	u := e.Ctx(t, "engineer@rel.test")
	record := must[*service.Record](t)(e.C.Records.Create(ctx, u, "notes", in(`{"tag":"before"}`)))
	e.Admin(t, `ALTER TABLE audit_events ADD CONSTRAINT test_audit_unavailable CHECK(action<>'record.update')`)
	u.OpID = "batch-audit-failure-operation"
	if _, err := e.C.Records.Batch(ctx, u, []service.BatchOperation{batchUpdate(record.ID, 1, "after")}); err == nil {
		t.Fatal("batch committed without its audit event")
	}
	got := must[*service.Record](t)(e.C.Records.Get(ctx, u, "notes", record.ID))
	if got.Version != 1 {
		t.Fatal("audit failure left a partial write")
	}
	var n int
	if err := e.Migrator.QueryRow(ctx, `SELECT count(*) FROM operation_receipts WHERE app=$1 AND op_id=$2`, testenv.App, u.OpID).Scan(&n); err != nil || n != 0 {
		t.Fatalf("audit failure left receipt %d %v", n, err)
	}
}

func TestBatchChecksClassificationBeforeWaitingOnHiddenRows(t *testing.T) {
	e, ctx := testenv.New(t), context.Background()
	must[*service.Collection](t)(e.C.Records.CreateCollection(ctx, e.Ctx(t, "admin@rel.test"), service.CollectionInput{Name: "controlled", Marking: cuiExpt}))
	inputRecord := in(`{"tag":"private"}`)
	inputRecord.Visibility = "app"
	record := must[*service.Record](t)(e.C.Records.Create(ctx, e.Ctx(t, "engineer@rel.test"), "controlled", inputRecord))
	e.Admin(t, `UPDATE app_members SET role='editor' WHERE app=$1 AND subject='intern@rel.test'`, testenv.App)
	tx, err := e.Migrator.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(ctx)
	if _, err := tx.Exec(ctx, `SET LOCAL ROLE strongbox_owner`); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(ctx, `SELECT id FROM records WHERE app=$1 AND id=$2 FOR UPDATE`, testenv.App, record.ID); err != nil {
		t.Fatal(err)
	}
	intern := e.Ctx(t, "intern@rel.test")
	intern.OpID = "batch-hidden-row-operation"
	call, cancel := context.WithTimeout(ctx, 500*time.Millisecond)
	defer cancel()
	input := in(`{"tag":"attempt"}`)
	_, err = e.C.Records.Batch(call, intern, []service.BatchOperation{{Type: "update", Collection: "controlled", ID: record.ID, ExpectedVersion: 1, Record: &input}})
	wantCode(t, err, "not_found")
}
