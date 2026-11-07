package service_test

import (
	"context"
	"fmt"
	"sync"
	"testing"

	"github.com/paulmalmquist/storage_relspace/internal/service"
	"github.com/paulmalmquist/storage_relspace/internal/testenv"
)

func obj(props map[string]any, required ...string) map[string]any {
	out := map[string]any{"type": "object", "properties": props}
	if len(required) > 0 {
		r := make([]any, len(required))
		for i, f := range required {
			r[i] = f
		}
		out["required"] = r
	}
	return out
}

func TestCompatibleContractChangeIsImmediate(t *testing.T) {
	env, ctx := testenv.New(t), context.Background()
	adm, eng := env.Ctx(t, "admin@rel.test"), env.Ctx(t, "engineer@rel.test")
	v1 := obj(map[string]any{"title": map[string]any{"type": "string", "maxLength": 20}}, "title")
	if _, err := env.C.Records.CreateCollection(ctx, adm, service.CollectionInput{Name: "tasks", Marking: cuiExpt, JSONSchema: v1}); err != nil {
		t.Fatal(err)
	}
	rec := must[*service.Record](t)(env.C.Records.Create(ctx, eng, "tasks", service.RecordInput{Data: map[string]any{"title": "a"}}))
	if rec.SchemaVersion == nil || *rec.SchemaVersion != 1 {
		t.Fatalf("schema version %v", rec.SchemaVersion)
	}
	// Wider: a longer limit and a new optional property... which existing records might already
	// hold with another type, so that one is not provably compatible.
	wider := obj(map[string]any{"title": map[string]any{"type": "string", "maxLength": 200}})
	ch := must[*service.ContractChange](t)(env.C.Records.ChangeContract(ctx, adm, "tasks", service.ContractInput{JSONSchema: wider, ExpectedVersion: 1}))
	if !ch.Immediate || ch.Collection.Version != 2 {
		t.Fatalf("widening change: %+v", ch)
	}
	withNew := obj(map[string]any{"title": map[string]any{"type": "string"}, "due": map[string]any{"type": "string"}})
	ch = must[*service.ContractChange](t)(env.C.Records.ChangeContract(ctx, adm, "tasks", service.ContractInput{JSONSchema: withNew, ExpectedVersion: 2}))
	if ch.Immediate || ch.Migration == nil || ch.Collection.Version != 2 || ch.Collection.Pending == nil {
		t.Fatalf("new property should need a migration: %+v", ch)
	}
	// Stale expected version and a second change while one is pending are refused.
	_, err := env.C.Records.ChangeContract(ctx, adm, "tasks", service.ContractInput{JSONSchema: withNew, ExpectedVersion: 2})
	wantCode(t, err, "migration_in_progress")
	// Viewers and members cannot change contracts.
	_, err = env.C.Records.ChangeContract(ctx, env.Ctx(t, "teammate@rel.test"), "tasks", service.ContractInput{JSONSchema: wider, ExpectedVersion: 2})
	wantCode(t, err, "forbidden")

	if _, err := env.C.Worker.RunOnce(ctx); err != nil {
		t.Fatal(err)
	}
	col := must[*service.Collection](t)(env.C.Records.GetCollection(ctx, eng, "tasks"))
	if col.Version != 3 || col.Pending != nil {
		t.Fatalf("after migration: version %d pending %v", col.Version, col.Pending)
	}
	vs := must[[]service.ContractVersion](t)(env.C.Records.ContractVersions(ctx, eng, "tasks"))
	if len(vs) != 3 || !vs[0].Current {
		t.Fatalf("versions %+v", vs)
	}
	_, err = env.C.Records.ChangeContract(ctx, adm, "tasks", service.ContractInput{JSONSchema: wider, ExpectedVersion: 2})
	wantCode(t, err, "precondition_failed")
}

func TestMigrationAppliesDefaultsValidatesAndIndexes(t *testing.T) {
	env, ctx := testenv.New(t), context.Background()
	adm, eng := env.Ctx(t, "admin@rel.test"), env.Ctx(t, "engineer@rel.test")
	v1 := obj(map[string]any{"sku": map[string]any{"type": "string"}})
	if _, err := env.C.Records.CreateCollection(ctx, adm, service.CollectionInput{Name: "parts", Marking: cuiExpt, JSONSchema: v1}); err != nil {
		t.Fatal(err)
	}
	const n = 450 // more than two batches
	for i := range n {
		if _, err := env.C.Records.Create(ctx, eng, "parts", service.RecordInput{Data: map[string]any{"sku": fmt.Sprintf("S-%04d", i)}}); err != nil {
			t.Fatal(err)
		}
	}
	// v2: status becomes required (default "active"), sku becomes indexed and unique.
	v2 := obj(map[string]any{"sku": map[string]any{"type": "string"}, "status": map[string]any{"enum": []any{"active", "retired"}}}, "sku", "status")
	ch := must[*service.ContractChange](t)(env.C.Records.ChangeContract(ctx, adm, "parts", service.ContractInput{JSONSchema: v2,
		IndexedFields: []string{"sku"}, UniqueFields: []string{"sku"}, Defaults: map[string]any{"status": "active"}, ExpectedVersion: 1}))
	if ch.Migration == nil {
		t.Fatalf("expected a migration: %+v", ch)
	}
	// While pending, writes must satisfy both contracts and claim uniqueness at once.
	_, err := env.C.Records.Create(ctx, eng, "parts", service.RecordInput{Data: map[string]any{"sku": "NEW-1"}})
	wantCode(t, err, "validation_failed") // v2 requires status
	if _, err := env.C.Records.Create(ctx, eng, "parts", service.RecordInput{Data: map[string]any{"sku": "NEW-1", "status": "active"}}); err != nil {
		t.Fatal(err)
	}
	_, err = env.C.Records.Create(ctx, eng, "parts", service.RecordInput{Data: map[string]any{"sku": "NEW-1", "status": "retired"}})
	wantCode(t, err, "unique_violation")

	if _, err := env.C.Worker.RunOnce(ctx); err != nil {
		t.Fatal(err)
	}
	m := must[*service.Migration](t)(env.C.Records.GetMigration(ctx, eng, "parts", ch.Migration.ID))
	if m.State != "succeeded" || m.Processed < n || m.Rewritten != n || len(m.Failures) != 0 {
		t.Fatalf("migration %+v", m)
	}
	recs, _ := must2(env.C.Records.Query(ctx, eng, "parts", map[string]any{"sku": "S-0042"}, 10, ""))
	if len(recs) != 1 || recs[0].Data["status"] != "active" || recs[0].Version != 2 || *recs[0].SchemaVersion != 2 {
		t.Fatalf("migrated record %+v", recs)
	}
	// The rewrite is in history, so undo works.
	hist, _, _ := env.C.Records.History(ctx, eng, "parts", recs[0].ID, 0, 0)
	if len(hist) != 2 || hist[0].Op != "migrate" {
		t.Fatalf("history %+v", hist)
	}
	// After the switch, uniqueness holds for everything, old records included.
	_, err = env.C.Records.Create(ctx, eng, "parts", service.RecordInput{Data: map[string]any{"sku": "S-0001", "status": "active"}})
	wantCode(t, err, "unique_violation")
	// Deleting releases the value.
	if err := env.C.Records.Delete(ctx, eng, "parts", recs[0].ID, nil, false); err != nil {
		t.Fatal(err)
	}
	if _, err := env.C.Records.Create(ctx, eng, "parts", service.RecordInput{Data: map[string]any{"sku": "S-0042", "status": "active"}}); err != nil {
		t.Fatalf("after delete: %v", err)
	}
}

func TestFailedMigrationLeavesTheCollectionAlone(t *testing.T) {
	env, ctx := testenv.New(t), context.Background()
	adm, eng := env.Ctx(t, "admin@rel.test"), env.Ctx(t, "engineer@rel.test")
	if _, err := env.C.Records.CreateCollection(ctx, adm, service.CollectionInput{Name: "parts", Marking: cuiExpt}); err != nil {
		t.Fatal(err)
	}
	for _, sku := range []string{"A", "B", "A"} { // a duplicate
		must[*service.Record](t)(env.C.Records.Create(ctx, eng, "parts", service.RecordInput{Data: map[string]any{"sku": sku}}))
	}
	ch := must[*service.ContractChange](t)(env.C.Records.ChangeContract(ctx, adm, "parts", service.ContractInput{
		JSONSchema: map[string]any{"type": "object"}, IndexedFields: []string{"sku"}, UniqueFields: []string{"sku"}, ExpectedVersion: 1}))
	if _, err := env.C.Worker.RunOnce(ctx); err != nil {
		t.Fatal(err)
	}
	m := must[*service.Migration](t)(env.C.Records.GetMigration(ctx, eng, "parts", ch.Migration.ID))
	if m.State != "failed" || len(m.Failures) != 1 || m.Failures[0].Reason != "another record already has this sku" {
		t.Fatalf("migration %+v", m)
	}
	col := must[*service.Collection](t)(env.C.Records.GetCollection(ctx, eng, "parts"))
	if col.Version != 1 || col.Pending != nil || len(col.UniqueFields) != 0 {
		t.Fatalf("collection changed: %+v", col)
	}
	// Writes are back to the old contract: duplicates allowed, no leftover uniqueness claims.
	if _, err := env.C.Records.Create(ctx, eng, "parts", service.RecordInput{Data: map[string]any{"sku": "B"}}); err != nil {
		t.Fatalf("after failed migration: %v", err)
	}
	// Cancelling a running migration also restores the old contract.
	ch = must[*service.ContractChange](t)(env.C.Records.ChangeContract(ctx, adm, "parts", service.ContractInput{
		JSONSchema: map[string]any{"type": "object"}, IndexedFields: []string{"sku"}, ExpectedVersion: 1}))
	if _, err := env.C.Records.CancelMigration(ctx, adm, "parts", ch.Migration.ID); err != nil {
		t.Fatal(err)
	}
	if col := must[*service.Collection](t)(env.C.Records.GetCollection(ctx, eng, "parts")); col.Pending != nil || col.Version != 1 {
		t.Fatalf("after cancel: %+v", col)
	}
}

// Writers that race a contract change either finish before it is staged or see it.
func TestContractChangeRacesWriters(t *testing.T) {
	env, ctx := testenv.New(t), context.Background()
	adm, eng := env.Ctx(t, "admin@rel.test"), env.Ctx(t, "engineer@rel.test")
	if _, err := env.C.Records.CreateCollection(ctx, adm, service.CollectionInput{Name: "notes", Marking: cuiExpt}); err != nil {
		t.Fatal(err)
	}
	strict := obj(map[string]any{"n": map[string]any{"type": "integer"}}, "n")
	var wg sync.WaitGroup
	for i := range 40 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			data := map[string]any{"n": i}
			if i%2 == 0 {
				data = map[string]any{"text": "no n"} // valid only under v1
			}
			_, _ = env.C.Records.Create(ctx, eng, "notes", service.RecordInput{Data: data})
		}()
	}
	ch, err := env.C.Records.ChangeContract(ctx, adm, "notes", service.ContractInput{JSONSchema: strict, ExpectedVersion: 1})
	wg.Wait()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := env.C.Worker.RunOnce(ctx); err != nil {
		t.Fatal(err)
	}
	m := must[*service.Migration](t)(env.C.Records.GetMigration(ctx, eng, "notes", ch.Migration.ID))
	if m.State == "failed" {
		return // the job found the records written under v1 before the change was staged
	}
	// The collection switched: then no record may lack n.
	recs, _ := must2(env.C.Records.Query(ctx, eng, "notes", nil, 200, ""))
	for _, r := range recs {
		if _, ok := r.Data["n"]; !ok {
			t.Fatalf("record %s is invalid under the active contract (migration %+v)", r.ID, m)
		}
	}
}

func must2[A, B any](a A, b B, err error) (A, B) {
	if err != nil {
		panic(err)
	}
	return a, b
}
