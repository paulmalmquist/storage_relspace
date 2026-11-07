package admin_test

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/paulmalmquist/storage_relspace/internal/admin"
	"github.com/paulmalmquist/storage_relspace/internal/crypto"
	"github.com/paulmalmquist/storage_relspace/internal/errs"
	"github.com/paulmalmquist/storage_relspace/internal/service"
	"github.com/paulmalmquist/storage_relspace/internal/testenv"
)

// seedLegacy writes rows the way the pre-app-scoping service did (0001 layout, v1/v2 contexts),
// then they are migrated into the '_legacy' scope exactly as 0002 does for existing data.
func seedLegacy(t *testing.T, env *testenv.Env) (recID, plainID, blobID string, payload []byte) {
	t.Helper()
	ctx := context.Background()
	key := crypto.NewDataKey()
	wrapped, err := env.C.KMS.Wrap(ctx, key, []byte("strongbox/datakey/v1|dk_legacy|collection:ncr|data"))
	if err != nil {
		t.Fatal(err)
	}
	metaKey := crypto.NewDataKey()
	metaWrapped, _ := env.C.KMS.Wrap(ctx, metaKey, []byte("strongbox/datakey/v1|dk_legacymeta|blobmeta|data"))
	env.Admin(t, `INSERT INTO data_keys (app, id, scope, purpose, kek_id, wrapped_key, aad_version) VALUES
		('_legacy','dk_legacy','collection:ncr','data',$1,$2,1), ('_legacy','dk_legacymeta','blobmeta','data',$1,$3,1)`,
		wrapped.KEKID, wrapped.Ciphertext, metaWrapped.Ciphertext)
	env.Admin(t, `INSERT INTO collections (app, name, marking, encrypted, json_schema, created_by, token_version) VALUES
		('_legacy','ncr','CUI//SP-EXPT',true,'{"type":"object"}','engineer@rel.test',1),
		('_legacy','open','UNCONTROLLED',false,'{"type":"object"}','engineer@rel.test',1)`)
	recID, plainID, blobID = "rec_legacy0001", "rec_legacy0002", "blb_legacy0001"
	sealed, _ := crypto.Seal(key, []byte(`{"part_number":"OLD-1"}`), []byte("strongbox/record/v1|ncr|"+recID+"|CUI//SP-EXPT|1"))
	env.Admin(t, `INSERT INTO records (app, id, collection, marking, data_sealed, key_id, version, created_by, updated_by, owner, visibility, aad_version)
		VALUES ('_legacy',$1,'ncr','CUI//SP-EXPT',$2,'dk_legacy',1,'engineer@rel.test','engineer@rel.test','engineer@rel.test','private',1)`, recID, sealed)
	// Written by the old defect: controlled content in plaintext. The NOT VALID constraint lets the
	// row exist; assignment must seal it.
	env.Admin(t, `ALTER TABLE records DROP CONSTRAINT records_plain_only_uncontrolled`)
	env.Admin(t, `INSERT INTO records (app, id, collection, marking, data_plain, version, created_by, updated_by, owner, visibility, aad_version)
		VALUES ('_legacy',$1,'open','CUI//PROPIN','{"secret":"plaintext cui"}',1,'engineer@rel.test','engineer@rel.test','engineer@rel.test','private',1)`, plainID)
	env.Admin(t, `ALTER TABLE records ADD CONSTRAINT records_plain_only_uncontrolled CHECK (data_plain IS NULL OR marking = 'UNCONTROLLED') NOT VALID`)
	// A legacy blob: v2 contexts, object at the pre-app key layout.
	dek := crypto.NewDataKey()
	wdek, _ := env.C.KMS.Wrap(ctx, dek, []byte("strongbox/blob-dek/v2|"+blobID+"|CUI//SP-EXPT"))
	sm, _ := crypto.Seal(metaKey, []byte(`{"filename":"old.bin","metadata":{}}`), []byte("strongbox/blob-meta/v2|"+blobID+"|CUI//SP-EXPT"))
	enc, _ := crypto.NewStreamEncryptor(dek, []byte("strongbox/blob/v2|"+blobID+"|CUI//SP-EXPT"), 4096)
	payload = bytes.Repeat([]byte("legacy "), 1000)
	var obj bytes.Buffer
	obj.Write(enc.Header())
	body, _ := enc.Update(payload)
	obj.Write(body)
	tail, _ := enc.Finalize()
	obj.Write(tail)
	path := filepath.Join(env.BlobDir, blobID[len(blobID)-2:], blobID)
	_ = os.MkdirAll(filepath.Dir(path), 0o700)
	if err := os.WriteFile(path, obj.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	env.Admin(t, `INSERT INTO blobs (app, id, state, marking, content_type, size_bytes, chunk_size, kek_id, wrapped_dek, meta_key_id, sealed_meta,
		storage_key, created_by, owner, visibility, aad_version) VALUES ('_legacy',$1,'active','CUI//SP-EXPT','application/octet-stream',$2,4096,$3,$4,
		'dk_legacymeta',$5,$1,'engineer@rel.test','engineer@rel.test','private',2)`, blobID, len(payload), wdek.KEKID, wdek.Ciphertext, sm)
	return recID, plainID, blobID, payload
}

func TestLegacyAssignment(t *testing.T) {
	env, ctx := testenv.New(t), context.Background()
	recID, plainID, blobID, payload := seedLegacy(t, env)
	eng := env.Ctx(t, "engineer@rel.test")
	if _, err := env.C.Records.Get(ctx, eng, "ncr", recID); !errs.Is(err, "not_found") {
		t.Fatalf("legacy row visible before assignment: %v", err)
	}
	a := &admin.Admin{Pool: env.Migrator, KMS: env.C.KMS, Actor: "admin-cli:test", Stripes: 4}

	rep, err := a.AssignLegacy(ctx, env.C.Keys, testenv.App, true, true)
	if err != nil || rep.Rows["records"] != 2 || rep.Rows["blobs"] != 1 || rep.PlaintextCUI != 1 || rep.Verified != 2 {
		t.Fatalf("dry run: %v %+v", err, rep)
	}
	if _, err := env.C.Records.Get(ctx, eng, "ncr", recID); !errs.Is(err, "not_found") {
		t.Fatal("dry run moved data")
	}

	rep, err = a.AssignLegacy(ctx, env.C.Keys, testenv.App, false, true)
	if err != nil || rep.Sealed != 1 {
		t.Fatalf("assign: %v %+v", err, rep)
	}
	got, err := env.C.Records.Get(ctx, eng, "ncr", recID)
	if err != nil || got.Data["part_number"] != "OLD-1" || got.Owner != "engineer@rel.test" || got.Visibility != "private" {
		t.Fatalf("legacy record after assignment: %v %+v", err, got)
	}
	// Still private: another member cannot see it.
	if _, err := env.C.Records.Get(ctx, env.Ctx(t, "teammate@rel.test"), "ncr", recID); !errs.Is(err, "not_found") {
		t.Fatal("legacy data became shared")
	}
	var plainNull bool
	_ = env.Migrator.QueryRow(ctx, `SELECT data_plain IS NULL FROM records WHERE id = $1`, plainID).Scan(&plainNull)
	if !plainNull {
		t.Fatal("controlled plaintext not sealed")
	}
	sealed, err := env.C.Records.Get(ctx, eng, "open", plainID)
	if err != nil || sealed.Data["secret"] != "plaintext cui" {
		t.Fatalf("sealed legacy record: %v", err)
	}
	_, body, err := env.C.Blobs.ReadAll(ctx, eng, blobID)
	if err != nil || !bytes.Equal(body, payload) {
		t.Fatalf("legacy blob: %v", err)
	}
	// Updating a legacy record re-seals it under the app-bound context.
	if _, err := env.C.Records.Update(ctx, eng, "ncr", recID, service.RecordInput{Data: map[string]any{"part_number": "OLD-1b"}}, 1); err != nil {
		t.Fatal(err)
	}
	var aad int
	_ = env.Migrator.QueryRow(ctx, `SELECT aad_version FROM records WHERE id = $1`, recID).Scan(&aad)
	if aad != 2 {
		t.Fatalf("aad_version %d after update", aad)
	}
	rep, _ = a.AssignLegacy(ctx, env.C.Keys, testenv.App, true, false)
	if rep.Rows["records"] != 0 {
		t.Fatal("legacy rows left behind")
	}
}

func TestLegacyAssignmentVerificationFailureMovesNothing(t *testing.T) {
	env, ctx := testenv.New(t), context.Background()
	recID, _, _, _ := seedLegacy(t, env)
	env.Admin(t, `UPDATE records SET marking = 'CUI//PROPIN' WHERE id = $1`, recID) // breaks the AAD
	a := &admin.Admin{Pool: env.Migrator, KMS: env.C.KMS, Actor: "admin-cli:test", Stripes: 4}
	rep, err := a.AssignLegacy(ctx, env.C.Keys, testenv.App, false, true)
	if err == nil || len(rep.Failures) != 1 {
		t.Fatalf("verification failure not reported: %v %+v", err, rep)
	}
	var left int
	_ = env.Migrator.QueryRow(ctx, `SELECT count(*) FROM records WHERE app = '_legacy'`).Scan(&left)
	if left != 2 {
		t.Fatalf("%d legacy records left (want 2: all-or-nothing)", left)
	}
}

func TestPrivilegedOperations(t *testing.T) {
	env, ctx := testenv.New(t), context.Background()
	a := &admin.Admin{Pool: env.Migrator, KMS: env.C.KMS, Actor: "admin-cli:test", Stripes: 4}
	if err := a.CreateApp(ctx, "fresh:test", "Fresh", "admin@rel.test"); err != nil {
		t.Fatal(err)
	}
	fresh := env.CtxIn(t, "fresh:test", "admin@rel.test")
	if info, err := env.C.Sharing.App(ctx, fresh); err != nil || info.Role != "admin" {
		t.Fatalf("first admin: %v %+v", err, info)
	}
	if err := a.CreateApp(ctx, "Bad App", "", "engineer@rel.test"); !errs.Is(err, "validation_failed") {
		t.Fatal(err)
	}
	if _, err := env.C.Records.CreateCollection(ctx, fresh, service.CollectionInput{Name: "notes"}); err != nil {
		t.Fatal(err)
	}
	r, err := env.C.Records.Create(ctx, fresh, "notes", service.RecordInput{Data: map[string]any{"a": 1}})
	if err != nil {
		t.Fatal(err)
	}
	if err := a.SetMember(ctx, "fresh:test", "teammate@rel.test", "member"); err != nil {
		t.Fatal(err)
	}
	if err := a.TransferOwner(ctx, "fresh:test", "record", r.ID, "teammate@rel.test"); err != nil {
		t.Fatal(err)
	}
	if got, err := env.C.Records.Get(ctx, env.CtxIn(t, "fresh:test", "teammate@rel.test"), "notes", r.ID); err != nil || got.Owner != "teammate@rel.test" {
		t.Fatalf("after transfer: %v", err)
	}
	if err := a.TransferOwner(ctx, "fresh:test", "record", r.ID, "outsider@rel.test"); !errs.Is(err, "validation_failed") {
		t.Fatalf("transfer to a non-member: %v", err)
	}
	if err := a.SetAppStatus(ctx, "fresh:test", "suspended"); err != nil {
		t.Fatal(err)
	}
	if _, err := env.C.Records.Get(ctx, fresh, "notes", r.ID); !errs.Is(err, "not_found") {
		t.Fatal("suspended app still serving")
	}
	var events int
	_ = env.Migrator.QueryRow(ctx, `SELECT count(*) FROM audit_events WHERE app = 'fresh:test' AND actor = 'admin-cli:test'`).Scan(&events)
	if events != 4 {
		t.Fatalf("privileged operations audited %d times", events)
	}
}
