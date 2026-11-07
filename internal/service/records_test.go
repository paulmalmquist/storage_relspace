package service_test

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/paulmalmquist/storage_relspace/internal/markings"
	"github.com/paulmalmquist/storage_relspace/internal/service"
	"github.com/paulmalmquist/storage_relspace/internal/testenv"
)

var cuiExpt = markings.MustParse("CUI//SP-EXPT")

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
	_, err = env.C.Records.CreateCollection(ctx, env.Ctx(t, "engineer@rel.test"), service.CollectionInput{Name: "nope", Marking: cuiExpt})
	wantCode(t, err, "forbidden")
	ncr(t, env)
	_, err = env.C.Records.CreateCollection(ctx, admin, service.CollectionInput{Name: "ncr", Marking: cuiExpt})
	wantCode(t, err, "conflict")
	_, err = env.C.Records.CreateCollection(ctx, admin, service.CollectionInput{Name: "x1", Marking: cuiExpt,
		JSONSchema: map[string]any{"type": "object", "properties": map[string]any{"a": map[string]any{"type": "bogus"}}}})
	wantCode(t, err, "validation_failed")
}

func TestRecordCRUDWithVersions(t *testing.T) {
	env, ctx := testenv.New(t), context.Background()
	ncr(t, env)
	eng := env.Ctx(t, "engineer@rel.test")
	r, err := env.C.Records.Create(ctx, eng, "ncr", doc(`{"part_number":"TR-1042","status":"open","qty":3}`), nil, "")
	if err != nil || r.Version != 1 || r.Data["qty"] != json.Number("3") {
		t.Fatalf("create: %v %+v", err, r)
	}
	r2, err := env.C.Records.Update(ctx, eng, "ncr", r.ID, doc(`{"part_number":"TR-1042","status":"dispositioned","qty":3}`), 1, nil)
	if err != nil || r2.Version != 2 {
		t.Fatalf("update: %v", err)
	}
	_, err = env.C.Records.Update(ctx, eng, "ncr", r.ID, doc(`{"part_number":"x","status":"open"}`), 1, nil)
	wantCode(t, err, "precondition_failed")
	got, _ := env.C.Records.Get(ctx, eng, "ncr", r.ID)
	if got.Data["status"] != "dispositioned" {
		t.Fatalf("got %v", got.Data)
	}
	two := 2
	if err := env.C.Records.Delete(ctx, eng, "ncr", r.ID, &two, false); err != nil {
		t.Fatal(err)
	}
	_, err = env.C.Records.Get(ctx, eng, "ncr", r.ID)
	wantCode(t, err, "not_found")
}

func TestSchemaEnforced(t *testing.T) {
	env, ctx := testenv.New(t), context.Background()
	ncr(t, env)
	eng := env.Ctx(t, "engineer@rel.test")
	_, err := env.C.Records.Create(ctx, eng, "ncr", doc(`{"part_number":"TR-1","status":"bogus"}`), nil, "")
	wantCode(t, err, "validation_failed")
	if !strings.Contains(err.Error(), "status") {
		t.Errorf("error should name the field: %v", err)
	}
	_, err = env.C.Records.Create(ctx, eng, "ncr", doc(`{"part_number":"TR-1","status":"open","extra":1}`), nil, "")
	wantCode(t, err, "validation_failed")
}

func TestPlaintextNeverStored(t *testing.T) {
	env, ctx := testenv.New(t), context.Background()
	ncr(t, env)
	_, err := env.C.Records.Create(ctx, env.Ctx(t, "engineer@rel.test"), "ncr",
		doc(`{"part_number":"TR-SECRET-77","status":"open","defect":"porosity in manifold"}`), nil, "")
	if err != nil {
		t.Fatal(err)
	}
	var sealed []byte
	var plainNull bool
	_ = env.C.DB.QueryRow(ctx, `SELECT data_sealed, data_plain IS NULL FROM records`).Scan(&sealed, &plainNull)
	if !plainNull || bytes.Contains(sealed, []byte("porosity")) {
		t.Fatal("record content stored in plaintext")
	}
	rows, _ := env.C.DB.Query(ctx, `SELECT token FROM record_index`)
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
		if _, err := env.C.Records.Create(ctx, eng, "ncr", doc(d), nil, ""); err != nil {
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
	a, _ := env.C.Records.Create(ctx, eng, "ncr", doc(`{"part_number":"A","status":"open"}`), nil, "")
	b, _ := env.C.Records.Create(ctx, eng, "ncr", doc(`{"part_number":"B","status":"open"}`), nil, "")
	if _, err := env.C.DB.Exec(ctx, `UPDATE records SET data_sealed=(SELECT data_sealed FROM records WHERE id=$2) WHERE id=$1`, a.ID, b.ID); err != nil {
		t.Fatal(err)
	}
	_, err := env.C.Records.Get(ctx, eng, "ncr", a.ID)
	wantCode(t, err, "integrity_violation")
}

func TestRecordMarkingRules(t *testing.T) {
	env, ctx := testenv.New(t), context.Background()
	ncr(t, env)
	eng := env.Ctx(t, "engineer@rel.test")
	lower := markings.MustParse("CUI//PROPIN")
	_, err := env.C.Records.Create(ctx, eng, "ncr", doc(`{"part_number":"A","status":"open"}`), &lower, "")
	wantCode(t, err, "validation_failed")
	higher := markings.MustParse("CUI//SP-EXPT//NOFORN")
	r, err := env.C.Records.Create(ctx, eng, "ncr", doc(`{"part_number":"A","status":"open"}`), &higher, "")
	if err != nil || r.Marking.Banner() != "CUI//SP-EXPT//NOFORN" {
		t.Fatalf("higher marking: %v", err)
	}
	_, err = env.C.Records.Update(ctx, eng, "ncr", r.ID, doc(`{"part_number":"A","status":"open"}`), 1, &cuiExpt)
	wantCode(t, err, "validation_failed")
}

func TestAccessFiltering(t *testing.T) {
	env, ctx := testenv.New(t), context.Background()
	ncr(t, env)
	r, _ := env.C.Records.Create(ctx, env.Ctx(t, "engineer@rel.test"), "ncr", doc(`{"part_number":"A","status":"open"}`), nil, "")
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
	items, _, _ := env.C.Records.Query(ctx, agent, "ncr", map[string]any{"part_number": "A"}, 0, "")
	if len(items) != 1 || !items[0].Withheld {
		t.Fatal("agent query should return withheld metadata")
	}
	cleared, _ := env.C.Records.Get(ctx, env.Ctx(t, "agent:boundary"), "ncr", r.ID)
	if cleared.Data["part_number"] != "A" {
		t.Fatal("cleared agent should see content")
	}
}

func TestIdempotentCreate(t *testing.T) {
	env, ctx := testenv.New(t), context.Background()
	ncr(t, env)
	eng := env.Ctx(t, "engineer@rel.test")
	a, _ := env.C.Records.Create(ctx, eng, "ncr", doc(`{"part_number":"A","status":"open"}`), nil, "abc")
	b, _ := env.C.Records.Create(ctx, eng, "ncr", doc(`{"part_number":"A","status":"open"}`), nil, "abc")
	if a.ID != b.ID {
		t.Fatal("replay created a second record")
	}
	_, err := env.C.Records.Create(ctx, eng, "ncr", doc(`{"part_number":"A","status":"closed"}`), nil, "abc")
	wantCode(t, err, "conflict")
}

func TestUncontrolledCollectionPlainStorage(t *testing.T) {
	env, ctx := testenv.New(t), context.Background()
	if _, err := env.C.Records.CreateCollection(ctx, env.Ctx(t, "admin@rel.test"), service.CollectionInput{
		Name: "tooling", Marking: markings.None(), IndexedFields: []string{"bay"}}); err != nil {
		t.Fatal(err)
	}
	eng := env.Ctx(t, "engineer@rel.test")
	if _, err := env.C.Records.Create(ctx, eng, "tooling", doc(`{"bay":4,"fixture":"F-12"}`), nil, ""); err != nil {
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
	r1, _ := env.C.Records.Create(ctx, eng, "ncr", doc(`{"part_number":"A","status":"open"}`), nil, "")
	env.C.Keys.Rotation = 0 // every key is now past its rotation window
	r2, _ := env.C.Records.Create(ctx, eng, "ncr", doc(`{"part_number":"B","status":"open"}`), nil, "")
	var k1, k2 string
	_ = env.C.DB.QueryRow(ctx, `SELECT key_id FROM records WHERE id=$1`, r1.ID).Scan(&k1)
	_ = env.C.DB.QueryRow(ctx, `SELECT key_id FROM records WHERE id=$1`, r2.ID).Scan(&k2)
	if k1 == k2 {
		t.Fatal("data key did not rotate")
	}
	env.C.Keys.ClearCache()
	got, err := env.C.Records.Get(ctx, eng, "ncr", r1.ID)
	if err != nil || got.Data["part_number"] != "A" {
		t.Fatalf("old key no longer decrypts: %v", err)
	}
}
