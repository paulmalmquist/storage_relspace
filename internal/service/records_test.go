package service_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"strings"
	"testing"

	"github.com/paulmalmquist/storage_relspace/internal/errs"
	"github.com/paulmalmquist/storage_relspace/internal/markings"
	"github.com/paulmalmquist/storage_relspace/internal/service"
	"github.com/paulmalmquist/storage_relspace/internal/testenv"
)

var (
	cuiExpt = markings.MustParse("CUI//SP-EXPT")
	expt    = markings.MustParse("CUI//SP-EXPT//NOFORN")
)

func randBytes(n int) []byte {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return b
}

func wantCode(t *testing.T, err error, code string) {
	t.Helper()
	if !errs.Is(err, code) {
		t.Fatalf("want %s, got %v", code, err)
	}
}

func must[T any](t *testing.T) func(T, error) T {
	return func(v T, err error) T {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
		return v
	}
}

func partSchema() map[string]any {
	var m map[string]any
	_ = json.Unmarshal([]byte(`{"type":"object","required":["part_number","status"],"additionalProperties":false,
		"properties":{"part_number":{"type":"string"},"status":{"type":"string","enum":["open","dispositioned","closed"]},
		"defect":{"type":"string"},"qty":{"type":"integer","minimum":0}}}`), &m)
	return m
}

func doc(s string) map[string]any {
	var m map[string]any
	dec := json.NewDecoder(strings.NewReader(s))
	dec.UseNumber()
	_ = dec.Decode(&m)
	return m
}

func in(s string) service.RecordInput { return service.RecordInput{Data: doc(s)} }

// shared is a record visible to every member of the app.
func shared(s string) service.RecordInput {
	return service.RecordInput{Data: doc(s), Visibility: "app"}
}

func ncr(t *testing.T, env *testenv.Env) {
	t.Helper()
	_, err := env.C.Records.CreateCollection(context.Background(), env.Ctx(t, "admin@rel.test"), service.CollectionInput{
		Name: "ncr", Marking: cuiExpt, JSONSchema: partSchema(), IndexedFields: []string{"part_number", "status"}})
	if err != nil {
		t.Fatal(err)
	}
}

func TestCollectionRules(t *testing.T) {
	env, ctx := testenv.New(t), context.Background()
	admin := env.Ctx(t, "admin@rel.test")
	no := false
	_, err := env.C.Records.CreateCollection(ctx, admin, service.CollectionInput{Name: "bad", Marking: cuiExpt, Encrypted: &no})
	wantCode(t, err, "validation_failed")
	// teammate is a member (not editor): may not define collections.
	_, err = env.C.Records.CreateCollection(ctx, env.Ctx(t, "teammate@rel.test"), service.CollectionInput{Name: "nope", Marking: cuiExpt})
	wantCode(t, err, "forbidden")
	ncr(t, env)
	_, err = env.C.Records.CreateCollection(ctx, admin, service.CollectionInput{Name: "ncr", Marking: cuiExpt})
	wantCode(t, err, "conflict")
	_, err = env.C.Records.CreateCollection(ctx, admin, service.CollectionInput{Name: "x1", Marking: cuiExpt,
		JSONSchema: map[string]any{"type": "object", "properties": map[string]any{"a": map[string]any{"type": "bogus"}}}})
	wantCode(t, err, "validation_failed")
	// The same collection name in another app is a different collection.
	if _, err := env.C.Records.CreateCollection(ctx, env.CtxIn(t, testenv.Other, "admin@rel.test"),
		service.CollectionInput{Name: "ncr", Marking: cuiExpt}); err != nil {
		t.Fatalf("per-app collection names: %v", err)
	}
}

func TestRecordCRUDWithVersions(t *testing.T) {
	env, ctx := testenv.New(t), context.Background()
	ncr(t, env)
	eng := env.Ctx(t, "engineer@rel.test")
	r, err := env.C.Records.Create(ctx, eng, "ncr", in(`{"part_number":"TR-1042","status":"open","qty":3}`))
	if err != nil || r.Version != 1 || r.Data["qty"] != json.Number("3") || r.Owner != "engineer@rel.test" || r.Visibility != "private" {
		t.Fatalf("create: %v %+v", err, r)
	}
	r2, err := env.C.Records.Update(ctx, eng, "ncr", r.ID, in(`{"part_number":"TR-1042","status":"dispositioned","qty":3}`), 1)
	if err != nil || r2.Version != 2 || r2.Data["status"] != "dispositioned" {
		t.Fatalf("update: %v", err)
	}
	_, err = env.C.Records.Update(ctx, eng, "ncr", r.ID, in(`{"part_number":"x","status":"open"}`), 1)
	wantCode(t, err, "precondition_failed")
	got, _ := env.C.Records.Get(ctx, eng, "ncr", r.ID)
	if got.Data["status"] != "dispositioned" {
		t.Fatalf("got %v", got.Data)
	}
	one, two := 1, 2
	wantCode(t, env.C.Records.Delete(ctx, eng, "ncr", r.ID, &one, false), "precondition_failed")
	if err := env.C.Records.Delete(ctx, eng, "ncr", r.ID, &two, false); err != nil {
		t.Fatal(err)
	}
	_, err = env.C.Records.Get(ctx, eng, "ncr", r.ID)
	wantCode(t, err, "not_found")
	// The deleted row keeps no content.
	var plainNull, sealedNull bool
	_ = env.Migrator.QueryRow(ctx, `SELECT data_plain IS NULL, data_sealed IS NULL FROM records WHERE id=$1`, r.ID).Scan(&plainNull, &sealedNull)
	if !plainNull || !sealedNull {
		t.Fatal("deleted record still holds content in its live row")
	}
}

func TestSchemaEnforced(t *testing.T) {
	env, ctx := testenv.New(t), context.Background()
	ncr(t, env)
	eng := env.Ctx(t, "engineer@rel.test")
	_, err := env.C.Records.Create(ctx, eng, "ncr", in(`{"part_number":"TR-1","status":"bogus"}`))
	wantCode(t, err, "validation_failed")
	if !strings.Contains(err.Error(), "status") {
		t.Errorf("error should name the field: %v", err)
	}
	_, err = env.C.Records.Create(ctx, eng, "ncr", in(`{"part_number":"TR-1","status":"open","extra":1}`))
	wantCode(t, err, "validation_failed")
}

func TestPlaintextNeverStored(t *testing.T) {
	env, ctx := testenv.New(t), context.Background()
	ncr(t, env)
	if _, err := env.C.Records.Create(ctx, env.Ctx(t, "engineer@rel.test"), "ncr",
		in(`{"part_number":"TR-SECRET-77","status":"open","defect":"porosity in manifold"}`)); err != nil {
		t.Fatal(err)
	}
	var sealed []byte
	var plainNull bool
	_ = env.Migrator.QueryRow(ctx, `SELECT data_sealed, data_plain IS NULL FROM records`).Scan(&sealed, &plainNull)
	if !plainNull || bytes.Contains(sealed, []byte("porosity")) {
		t.Fatal("record content stored in plaintext")
	}
	var revSealed []byte
	_ = env.Migrator.QueryRow(ctx, `SELECT data_sealed FROM record_revisions`).Scan(&revSealed)
	if bytes.Contains(revSealed, []byte("porosity")) || len(revSealed) == 0 {
		t.Fatal("history stored in plaintext")
	}
	rows, _ := env.Migrator.Query(ctx, `SELECT token FROM record_index`)
	for rows.Next() {
		var tok string
		_ = rows.Scan(&tok)
		if !strings.HasPrefix(tok, "b:") || strings.Contains(tok, "TR-SECRET") {
			t.Fatalf("index token leaks: %s", tok)
		}
	}
	rows.Close()
}

func TestBlindIndexQuery(t *testing.T) {
	env, ctx := testenv.New(t), context.Background()
	ncr(t, env)
	eng := env.Ctx(t, "engineer@rel.test")
	for _, d := range []string{`{"part_number":"TR-1","status":"open"}`, `{"part_number":"TR-1","status":"closed"}`, `{"part_number":"TR-2","status":"open"}`} {
		if _, err := env.C.Records.Create(ctx, eng, "ncr", in(d)); err != nil {
			t.Fatal(err)
		}
	}
	items, _, err := env.C.Records.Query(ctx, eng, "ncr", map[string]any{"part_number": "TR-1"}, 0, "")
	if err != nil || len(items) != 2 {
		t.Fatalf("query: %v %d", err, len(items))
	}
	items, _, _ = env.C.Records.Query(ctx, eng, "ncr", map[string]any{"part_number": "TR-1", "status": "open"}, 0, "")
	if len(items) != 1 {
		t.Fatalf("two-field query returned %d", len(items))
	}
	_, _, err = env.C.Records.Query(ctx, eng, "ncr", map[string]any{"defect": "x"}, 0, "")
	wantCode(t, err, "validation_failed")
}

func TestRowSwapDetected(t *testing.T) {
	env, ctx := testenv.New(t), context.Background()
	ncr(t, env)
	eng := env.Ctx(t, "engineer@rel.test")
	a := must[*service.Record](t)(env.C.Records.Create(ctx, eng, "ncr", in(`{"part_number":"A","status":"open"}`)))
	b := must[*service.Record](t)(env.C.Records.Create(ctx, eng, "ncr", in(`{"part_number":"B","status":"open"}`)))
	env.Admin(t, `UPDATE records SET data_sealed=(SELECT data_sealed FROM records WHERE id=$2) WHERE id=$1`, a.ID, b.ID)
	_, err := env.C.Records.Get(ctx, eng, "ncr", a.ID)
	wantCode(t, err, "integrity_violation")
}

// Ciphertext copied between apps does not authenticate: the AAD binds the app.
func TestCrossAppCiphertextSwapDetected(t *testing.T) {
	env, ctx := testenv.New(t), context.Background()
	ncr(t, env)
	eng := env.Ctx(t, "engineer@rel.test")
	a := must[*service.Record](t)(env.C.Records.Create(ctx, eng, "ncr", in(`{"part_number":"A","status":"open"}`)))
	// Rebuild the same collection, key and record id under the other app, carrying the ciphertext.
	env.Admin(t, `INSERT INTO data_keys (app, id, scope, purpose, kek_id, wrapped_key, aad_version, created_at)
		SELECT $1, id || 'x', scope, purpose, kek_id, wrapped_key, aad_version, created_at FROM data_keys WHERE app = $2`, testenv.Other, testenv.App)
	env.Admin(t, `INSERT INTO collections (app, name, marking, encrypted, indexed_fields, json_schema, index_key_id, created_by, token_version)
		SELECT $1, name, marking, encrypted, indexed_fields, json_schema, index_key_id || 'x', created_by, 2 FROM collections WHERE app = $2`, testenv.Other, testenv.App)
	env.Admin(t, `INSERT INTO records (app, id, collection, marking, data_sealed, key_id, version, created_by, updated_by, owner, visibility, aad_version)
		SELECT $1, id || 'x', collection, marking, data_sealed, key_id || 'x', version, 'admin@rel.test', 'admin@rel.test', 'admin@rel.test', 'private', 2
		FROM records WHERE id = $2`, testenv.Other, a.ID)
	_, err := env.C.Records.Get(ctx, env.CtxIn(t, testenv.Other, "admin@rel.test"), "ncr", a.ID+"x")
	wantCode(t, err, "integrity_violation")
}

func TestRecordMarkingRules(t *testing.T) {
	env, ctx := testenv.New(t), context.Background()
	ncr(t, env)
	eng := env.Ctx(t, "engineer@rel.test")
	lower := markings.MustParse("CUI//PROPIN")
	_, err := env.C.Records.Create(ctx, eng, "ncr", service.RecordInput{Data: doc(`{"part_number":"A","status":"open"}`), Marking: &lower})
	wantCode(t, err, "validation_failed")
	r, err := env.C.Records.Create(ctx, eng, "ncr", service.RecordInput{Data: doc(`{"part_number":"A","status":"open"}`), Marking: &expt})
	if err != nil || r.Marking.Banner() != "CUI//SP-EXPT//NOFORN" {
		t.Fatalf("higher marking: %v", err)
	}
	_, err = env.C.Records.Update(ctx, eng, "ncr", r.ID, service.RecordInput{Data: doc(`{"part_number":"A","status":"open"}`), Marking: &lower}, 1)
	wantCode(t, err, "validation_failed")
}

func TestAccessFiltering(t *testing.T) {
	env, ctx := testenv.New(t), context.Background()
	ncr(t, env)
	r := must[*service.Record](t)(env.C.Records.Create(ctx, env.Ctx(t, "engineer@rel.test"), "ncr", shared(`{"part_number":"A","status":"open"}`)))
	foreign := env.Ctx(t, "foreign@rel.test")
	_, err := env.C.Records.Get(ctx, foreign, "ncr", r.ID)
	wantCode(t, err, "not_found")
	_, _, err = env.C.Records.Query(ctx, foreign, "ncr", nil, 0, "")
	wantCode(t, err, "not_found")

	agent := env.Ctx(t, "agent:assistant")
	v, err := env.C.Records.Get(ctx, agent, "ncr", r.ID)
	if err != nil || !v.Withheld || v.Data != nil || !v.Marking.Equal(cuiExpt) {
		t.Fatalf("agent view: %v %+v", err, v)
	}
	items, _, _ := env.C.Records.Query(ctx, agent, "ncr", nil, 0, "")
	if len(items) != 1 || !items[0].Withheld {
		t.Fatal("agent listing should return withheld metadata")
	}
	cleared, _ := env.C.Records.Get(ctx, env.Ctx(t, "agent:boundary"), "ncr", r.ID)
	if cleared.Data["part_number"] != "A" {
		t.Fatal("cleared agent should see content")
	}
}

func TestUncontrolledCollectionPlainStorage(t *testing.T) {
	env, ctx := testenv.New(t), context.Background()
	if _, err := env.C.Records.CreateCollection(ctx, env.Ctx(t, "admin@rel.test"), service.CollectionInput{
		Name: "tooling", Marking: markings.None(), IndexedFields: []string{"bay"}}); err != nil {
		t.Fatal(err)
	}
	eng := env.Ctx(t, "engineer@rel.test")
	if _, err := env.C.Records.Create(ctx, eng, "tooling", in(`{"bay":4,"fixture":"F-12"}`)); err != nil {
		t.Fatal(err)
	}
	items, _, _ := env.C.Records.Query(ctx, eng, "tooling", map[string]any{"bay": json.Number("4.0")}, 0, "")
	if len(items) != 1 || items[0].Data["fixture"] != "F-12" {
		t.Fatalf("plain query: %d", len(items))
	}
}

func TestDataKeyRotation(t *testing.T) {
	env, ctx := testenv.New(t), context.Background()
	ncr(t, env)
	eng := env.Ctx(t, "engineer@rel.test")
	r1 := must[*service.Record](t)(env.C.Records.Create(ctx, eng, "ncr", in(`{"part_number":"A","status":"open"}`)))
	env.C.Keys.Rotation = 0 // every key is now past its rotation window
	r2 := must[*service.Record](t)(env.C.Records.Create(ctx, eng, "ncr", in(`{"part_number":"B","status":"open"}`)))
	var k1, k2 string
	_ = env.Migrator.QueryRow(ctx, `SELECT key_id FROM records WHERE id=$1`, r1.ID).Scan(&k1)
	_ = env.Migrator.QueryRow(ctx, `SELECT key_id FROM records WHERE id=$1`, r2.ID).Scan(&k2)
	if k1 == k2 {
		t.Fatal("data key did not rotate")
	}
	env.C.Keys.ClearCache()
	got, err := env.C.Records.Get(ctx, eng, "ncr", r1.ID)
	if err != nil || got.Data["part_number"] != "A" {
		t.Fatalf("old key no longer decrypts: %v", err)
	}
}

func TestPaginationAndCursorBinding(t *testing.T) {
	env, ctx := testenv.New(t), context.Background()
	ncr(t, env)
	eng := env.Ctx(t, "engineer@rel.test")
	for i := 0; i < 5; i++ {
		if _, err := env.C.Records.Create(ctx, eng, "ncr", in(`{"part_number":"P","status":"open"}`)); err != nil {
			t.Fatal(err)
		}
	}
	seen := map[string]bool{}
	cur := ""
	for {
		items, next, err := env.C.Records.Query(ctx, eng, "ncr", nil, 2, cur)
		if err != nil {
			t.Fatal(err)
		}
		for _, r := range items {
			seen[r.ID] = true
		}
		if next == "" {
			break
		}
		cur = next
	}
	if len(seen) != 5 {
		t.Fatalf("paged %d of 5", len(seen))
	}
	// A cursor is bound to its app and listing.
	_, next, _ := env.C.Records.Query(ctx, eng, "ncr", nil, 2, "")
	other := env.CtxIn(t, testenv.Other, "admin@rel.test")
	if _, err := env.C.Records.CreateCollection(ctx, other, service.CollectionInput{Name: "ncr", Marking: cuiExpt}); err != nil {
		t.Fatal(err)
	}
	_, _, err := env.C.Records.Query(ctx, other, "ncr", nil, 2, next)
	wantCode(t, err, "validation_failed")
	_, _, err = env.C.Blobs.List(ctx, eng, 2, next)
	wantCode(t, err, "validation_failed")
}
