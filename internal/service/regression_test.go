package service_test

// Regression tests for the review findings reproduced against main@8b3af49
// (docs/evidence/REPRODUCTIONS.md). Upload findings 4 and 5 are in blobs_test.go.

import (
	"context"
	"sync"
	"testing"

	"github.com/paulmalmquist/storage_relspace/internal/markings"
	"github.com/paulmalmquist/storage_relspace/internal/service"
	"github.com/paulmalmquist/storage_relspace/internal/testenv"
)

// Finding 1: controlled records cannot be stored in an unencrypted collection, by the service or
// by the database.
func TestControlledRecordNeverPlaintext(t *testing.T) {
	env, ctx := testenv.New(t), context.Background()
	no := false
	admin := env.Ctx(t, "admin@rel.test")
	if _, err := env.C.Records.CreateCollection(ctx, admin, service.CollectionInput{Name: "open", Marking: markings.None(), Encrypted: &no}); err != nil {
		t.Fatal(err)
	}
	_, err := env.C.Records.Create(ctx, admin, "open", service.RecordInput{Data: doc(`{"secret":"engine drawing"}`), Marking: &cuiExpt})
	wantCode(t, err, "validation_failed")
	r := must[*service.Record](t)(env.C.Records.Create(ctx, admin, "open", in(`{"ok":"public"}`)))
	_, err = env.C.Records.Update(ctx, admin, "open", r.ID, service.RecordInput{Data: doc(`{"ok":"now cui"}`), Marking: &cuiExpt}, 1)
	wantCode(t, err, "validation_failed")
	// Backstop: the database refuses the row even from a privileged writer.
	_, err = env.Migrator.Exec(ctx, `UPDATE records SET marking = 'CUI//SP-EXPT' WHERE id = $1`, r.ID)
	if err == nil {
		t.Fatal("database accepted controlled plaintext")
	}
}

// Finding 2: the response is the exact version this call wrote, authorized for this caller, even
// when another writer commits right after.
func TestSaveResponseIsTheWrittenVersion(t *testing.T) {
	env, ctx := testenv.New(t), context.Background()
	ncr(t, env)
	eng := env.Ctx(t, "engineer@rel.test")
	r := must[*service.Record](t)(env.C.Records.Create(ctx, eng, "ncr", shared(`{"part_number":"A","status":"open"}`)))
	var wg sync.WaitGroup
	results := make(chan *service.Record, 40)
	for i := 0; i < 40; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			for {
				cur, err := env.C.Records.Get(ctx, eng, "ncr", r.ID)
				if err != nil {
					t.Error(err)
					return
				}
				m := cuiExpt
				if i%2 == 1 {
					m = expt
				}
				status := []string{"open", "dispositioned"}[i%2]
				got, err := env.C.Records.Update(ctx, eng, "ncr", r.ID, service.RecordInput{
					Data: doc(`{"part_number":"A","status":"` + status + `"}`), Marking: &m}, cur.Version)
				if err == nil {
					results <- got
					return
				}
			}
		}(i)
	}
	wg.Wait()
	close(results)
	versions := map[int]bool{}
	for got := range results {
		if versions[got.Version] {
			t.Fatalf("two writers got version %d", got.Version)
		}
		versions[got.Version] = true
		// The returned data and marking belong together: odd writers wrote NOFORN + dispositioned.
		noforn := got.Marking.Equal(expt)
		if noforn != (got.Data["status"] == "dispositioned") {
			t.Fatalf("version %d returned %v with marking %s", got.Version, got.Data, got.Marking.Banner())
		}
	}
	if len(versions) != 40 {
		t.Fatalf("%d successful writes", len(versions))
	}
}

// Finding 3: a stale delete never removes a newer version, and update/delete races resolve to one
// winner.
func TestStaleDeleteAndUpdateDeleteRace(t *testing.T) {
	env, ctx := testenv.New(t), context.Background()
	ncr(t, env)
	eng := env.Ctx(t, "engineer@rel.test")
	r := must[*service.Record](t)(env.C.Records.Create(ctx, eng, "ncr", in(`{"part_number":"A","status":"open"}`)))
	must[*service.Record](t)(env.C.Records.Update(ctx, eng, "ncr", r.ID, in(`{"part_number":"A","status":"closed"}`), 1))
	one := 1
	wantCode(t, env.C.Records.Delete(ctx, eng, "ncr", r.ID, &one, false), "precondition_failed")
	if _, err := env.C.Records.Get(ctx, eng, "ncr", r.ID); err != nil {
		t.Fatal("stale delete removed the record")
	}
	for i := 0; i < 20; i++ {
		x := must[*service.Record](t)(env.C.Records.Create(ctx, eng, "ncr", in(`{"part_number":"R","status":"open"}`)))
		var wg sync.WaitGroup
		var updErr, delErr error
		v := 1
		wg.Add(2)
		go func() {
			defer wg.Done()
			_, updErr = env.C.Records.Update(ctx, eng, "ncr", x.ID, in(`{"part_number":"R","status":"closed"}`), 1)
		}()
		go func() { defer wg.Done(); delErr = env.C.Records.Delete(ctx, eng, "ncr", x.ID, &v, false) }()
		wg.Wait()
		if (updErr == nil) == (delErr == nil) {
			t.Fatalf("update err %v, delete err %v: exactly one must win", updErr, delErr)
		}
		var indexRows int
		_ = env.Migrator.QueryRow(ctx, `SELECT count(*) FROM record_index WHERE record_id = $1`, x.ID).Scan(&indexRows)
		if delErr == nil && indexRows != 0 || updErr == nil && indexRows != 2 {
			t.Fatalf("index rows %d after update=%v delete=%v", indexRows, updErr == nil, delErr == nil)
		}
	}
}

// Finding 6: a retried update whose response was lost returns the original result instead of 412,
// and the receipt is resolved before the version precondition.
func TestLostResponseRetries(t *testing.T) {
	env, ctx := testenv.New(t), context.Background()
	ncr(t, env)
	eng := env.Ctx(t, "engineer@rel.test")
	eng.OpID = "create-0001"
	r := must[*service.Record](t)(env.C.Records.Create(ctx, eng, "ncr", in(`{"part_number":"A","status":"open"}`)))
	again := must[*service.Record](t)(env.C.Records.Create(ctx, eng, "ncr", in(`{"part_number":"A","status":"open"}`)))
	if again.ID != r.ID || !again.Replayed || again.Version != 1 {
		t.Fatalf("create replay: %+v", again)
	}
	eng.OpID = "update-0001"
	u := must[*service.Record](t)(env.C.Records.Update(ctx, eng, "ncr", r.ID, in(`{"part_number":"A","status":"closed"}`), 1))
	eng.OpID = "update-0002"
	must[*service.Record](t)(env.C.Records.Update(ctx, eng, "ncr", r.ID, in(`{"part_number":"A","status":"dispositioned"}`), 2))
	eng.OpID = "update-0001" // the first update's response was lost; the client retries it
	replayed := must[*service.Record](t)(env.C.Records.Update(ctx, eng, "ncr", r.ID, in(`{"part_number":"A","status":"closed"}`), 1))
	if replayed.Version != u.Version || replayed.Data["status"] != "closed" || !replayed.Replayed {
		t.Fatalf("replay returned %+v", replayed)
	}
	rc := must[*service.Receipt](t)(env.C.Operation(ctx, eng, "update-0001"))
	if rc.Status != "succeeded" || rc.ResourceVersion != 2 {
		t.Fatalf("receipt %+v", rc)
	}
	eng.OpID = "delete-0001"
	three := 3
	if err := env.C.Records.Delete(ctx, eng, "ncr", r.ID, &three, false); err != nil {
		t.Fatal(err)
	}
	if err := env.C.Records.Delete(ctx, eng, "ncr", r.ID, &three, false); err != nil {
		t.Fatalf("retried delete: %v", err)
	}
}

// Finding 7: receipts are namespaced by app, subject and actor, and keyed fingerprints detect a
// changed operation without storing a guessable digest.
func TestReceiptNamespaceAndFingerprint(t *testing.T) {
	env, ctx := testenv.New(t), context.Background()
	ncr(t, env)
	user := env.Ctx(t, "engineer@rel.test")
	user.OpID = "shared-key-01"
	a := must[*service.Record](t)(env.C.Records.Create(ctx, user, "ncr", in(`{"part_number":"A","status":"open"}`)))
	agent := env.OnBehalf(t, "engineer@rel.test", "agent:assistant")
	agent.OpID = "shared-key-01"
	b := must[*service.Record](t)(env.C.Records.Create(ctx, agent, "ncr", in(`{"part_number":"A","status":"open"}`)))
	if a.ID == b.ID {
		t.Fatal("agent acting for the user replayed the user's own operation")
	}
	_, err := env.C.Records.Create(ctx, user, "ncr", in(`{"part_number":"A","status":"closed"}`))
	wantCode(t, err, "idempotency_key_reused")
	_, err = env.C.Records.Create(ctx, user, "ncr", service.RecordInput{Data: doc(`{"part_number":"A","status":"open"}`), Marking: &expt})
	wantCode(t, err, "idempotency_key_reused")
	_, err = env.C.Records.Update(ctx, user, "ncr", a.ID, in(`{"part_number":"A","status":"open"}`), 1)
	wantCode(t, err, "idempotency_key_reused") // same ID, different operation type and target
	// Another app's receipts are a different namespace.
	other := env.CtxIn(t, testenv.Other, "admin@rel.test")
	if _, err := env.C.Records.CreateCollection(ctx, other, service.CollectionInput{Name: "ncr", Marking: cuiExpt}); err != nil {
		t.Fatal(err)
	}
	other.OpID = "shared-key-01"
	if _, err := env.C.Records.Create(ctx, other, "ncr", in(`{"x":1}`)); err != nil {
		t.Fatalf("receipt namespace leaked across apps: %v", err)
	}
	// The stored fingerprint is an HMAC (32 bytes) keyed per app, not a digest of the payload.
	var fp []byte
	var keyPurpose string
	_ = env.Migrator.QueryRow(ctx, `SELECT r.fingerprint, k.purpose FROM operation_receipts r JOIN data_keys k
		ON k.app = r.app AND k.id = r.fp_key_id WHERE r.actor = 'engineer@rel.test' LIMIT 1`).Scan(&fp, &keyPurpose)
	if len(fp) != 32 || keyPurpose != "receipt" {
		t.Fatalf("fingerprint %d bytes, key purpose %q", len(fp), keyPurpose)
	}
	_, err = env.C.Records.Create(ctx, service.Ctx{Principal: user.Principal, App: testenv.App, OpID: "bad id!"}, "ncr", in(`{}`))
	wantCode(t, err, "validation_failed")
}

// Receipt replay does not outlive revocation.
func TestReplayAfterRevocation(t *testing.T) {
	env, ctx := testenv.New(t), context.Background()
	notes(t, env)
	eng, mate := env.Ctx(t, "engineer@rel.test"), env.Ctx(t, "teammate@rel.test")
	r := must[*service.Record](t)(env.C.Records.Create(ctx, eng, "notes", in(`{"tag":"x"}`)))
	g := must[*service.Grant](t)(env.C.Sharing.AddGrant(ctx, eng, service.ResourceRef{Kind: "record", Collection: "notes", ID: r.ID},
		service.GrantInput{Subject: "teammate@rel.test", Role: "editor"}))
	mate.OpID = "mate-update-1"
	must[*service.Record](t)(env.C.Records.Update(ctx, mate, "notes", r.ID, in(`{"tag":"y"}`), 1))
	if err := env.C.Sharing.RemoveGrant(ctx, eng, service.ResourceRef{Kind: "record", Collection: "notes", ID: r.ID}, g.ID); err != nil {
		t.Fatal(err)
	}
	_, err := env.C.Records.Update(ctx, mate, "notes", r.ID, in(`{"tag":"y"}`), 1)
	wantCode(t, err, "not_found")
}

// Finding 8: the audit event commits with the mutation; if the audit write fails, nothing commits.
func TestMutationAndAuditCommitTogether(t *testing.T) {
	env, ctx := testenv.New(t), context.Background()
	ncr(t, env)
	eng := env.Ctx(t, "engineer@rel.test")
	env.Admin(t, `CREATE FUNCTION `+env.Schema+`.no_audit() RETURNS trigger LANGUAGE plpgsql AS $$
		BEGIN IF NEW.action = 'record.create' THEN RAISE EXCEPTION 'audit sink down'; END IF; RETURN NEW; END $$;
		CREATE TRIGGER no_audit BEFORE INSERT ON `+env.Schema+`.audit_events FOR EACH ROW EXECUTE FUNCTION `+env.Schema+`.no_audit();`)
	if _, err := env.C.Records.Create(ctx, eng, "ncr", in(`{"part_number":"A","status":"open"}`)); err == nil {
		t.Fatal("create succeeded without its audit event")
	}
	var records, revisions int
	_ = env.Migrator.QueryRow(ctx, `SELECT (SELECT count(*) FROM records), (SELECT count(*) FROM record_revisions)`).Scan(&records, &revisions)
	if records != 0 || revisions != 0 {
		t.Fatalf("%d records, %d revisions committed without audit", records, revisions)
	}
	// Denials are audited even though the request transaction rolls back.
	_, _ = env.C.Records.Get(ctx, env.Ctx(t, "foreign@rel.test"), "ncr", "rec_nonexistent")
	_, err := env.C.Records.CreateCollection(ctx, env.Ctx(t, "teammate@rel.test"), service.CollectionInput{Name: "zz", Marking: cuiExpt})
	wantCode(t, err, "forbidden")
	var denials int
	_ = env.Migrator.QueryRow(ctx, `SELECT count(*) FROM audit_events WHERE decision = 'deny' AND action = 'collection.create'
		AND app = $1`, testenv.App).Scan(&denials)
	if denials != 1 {
		t.Fatalf("%d denial events", denials)
	}
}

// Finding 9: schemas are authorized before they are compiled, never load files or URLs, and are
// bounded.
func TestSchemaLoadingIsAuthorizedAndClosed(t *testing.T) {
	env, ctx := testenv.New(t), context.Background()
	viewer := env.Ctx(t, "intern@rel.test")
	_, err := env.C.Records.CreateCollection(ctx, viewer, service.CollectionInput{Name: "xx", Marking: markings.None(),
		JSONSchema: map[string]any{"$ref": "file:///etc/hostname"}})
	wantCode(t, err, "forbidden")
	admin := env.Ctx(t, "admin@rel.test")
	for _, ref := range []string{"file:///etc/hostname", "https://example.com/schema.json", "/etc/passwd"} {
		_, err = env.C.Records.CreateCollection(ctx, admin, service.CollectionInput{Name: "xx", Marking: markings.None(),
			JSONSchema: map[string]any{"type": "object", "properties": map[string]any{"a": map[string]any{"$ref": ref}}}})
		wantCode(t, err, "validation_failed")
	}
	deep := map[string]any{"type": "object"}
	for i := 0; i < 40; i++ {
		deep = map[string]any{"type": "object", "properties": map[string]any{"n": deep}}
	}
	_, err = env.C.Records.CreateCollection(ctx, admin, service.CollectionInput{Name: "deep", Marking: markings.None(), JSONSchema: deep})
	wantCode(t, err, "validation_failed")
}

// Disclosure: filtering is a content assertion. An agent denied content cannot learn indexed values
// by testing candidates; the filtered result is the same whether or not the value exists.
func TestFiltersAreNotAnOracle(t *testing.T) {
	env, ctx := testenv.New(t), context.Background()
	ncr(t, env)
	must[*service.Record](t)(env.C.Records.Create(ctx, env.Ctx(t, "engineer@rel.test"), "ncr", shared(`{"part_number":"SECRET-7","status":"open"}`)))
	agent := env.Ctx(t, "agent:assistant")
	hit, nextHit, err := env.C.Records.Query(ctx, agent, "ncr", map[string]any{"part_number": "SECRET-7"}, 1, "")
	if err != nil {
		t.Fatal(err)
	}
	miss, nextMiss, _ := env.C.Records.Query(ctx, agent, "ncr", map[string]any{"part_number": "NOPE"}, 1, "")
	if len(hit) != len(miss) || nextHit != nextMiss || len(hit) != 0 {
		t.Fatalf("filter oracle: hit=%d/%q miss=%d/%q", len(hit), nextHit, len(miss), nextMiss)
	}
	cleared, _, _ := env.C.Records.Query(ctx, env.Ctx(t, "agent:boundary"), "ncr", map[string]any{"part_number": "SECRET-7"}, 1, "")
	if len(cleared) != 1 {
		t.Fatal("agent inside the LLM boundary should be able to filter")
	}
}
