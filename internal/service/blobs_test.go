package service_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"os"
	"path/filepath"
	"testing"

	"github.com/paulmalmquist/storage_relspace/internal/errs"
	"github.com/paulmalmquist/storage_relspace/internal/markings"
	"github.com/paulmalmquist/storage_relspace/internal/service"
	"github.com/paulmalmquist/storage_relspace/internal/testenv"
)

var expt = markings.MustParse("CUI//SP-EXPT//NOFORN")

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

func TestBlobRoundTrip(t *testing.T) {
	env, ctx := testenv.New(t), context.Background()
	eng := env.Ctx(t, "engineer@rel.test")
	data := randBytes(1_000_003)
	meta, err := env.C.Blobs.Put(ctx, eng, data, service.BlobInput{Marking: expt, Filename: "weld-map.bin",
		Metadata: map[string]any{"part_number": "TR-1042", "lot": 7}})
	if err != nil {
		t.Fatal(err)
	}
	if *meta.SizeBytes != int64(len(data)) {
		t.Fatalf("size %d", *meta.SizeBytes)
	}
	got, body, err := env.C.Blobs.ReadAll(ctx, eng, meta.ID)
	if err != nil || !bytes.Equal(body, data) {
		t.Fatalf("round trip: %v", err)
	}
	if got.Filename != "weld-map.bin" || got.Metadata["part_number"] != "TR-1042" || !got.Marking.Equal(expt) {
		t.Fatalf("metadata %+v", got)
	}
}

func TestNothingSensitiveAtRest(t *testing.T) {
	env, ctx := testenv.New(t), context.Background()
	eng := env.Ctx(t, "engineer@rel.test")
	secret := bytes.Repeat([]byte("INJECTOR-PINTLE-GEOMETRY "), 400)
	meta, err := env.C.Blobs.Put(ctx, eng, secret, service.BlobInput{Marking: expt, Filename: "pintle-secret.txt",
		Metadata: map[string]any{"note": "HOTFIRE-DATA"}})
	if err != nil {
		t.Fatal(err)
	}
	disk, _ := os.ReadFile(env.ObjectPath(meta.ID))
	if bytes.Contains(disk, []byte("INJECTOR")) {
		t.Fatal("plaintext on disk")
	}
	var sealed, wrapped []byte
	if err := env.C.DB.QueryRow(ctx, `SELECT sealed_meta, wrapped_dek FROM blobs WHERE id=$1`, meta.ID).Scan(&sealed, &wrapped); err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(sealed, []byte("pintle")) || bytes.Contains(sealed, []byte("HOTFIRE")) || len(wrapped) <= 32 {
		t.Fatal("metadata or key not protected")
	}
}

func TestTamperedObjectDetectedAndAudited(t *testing.T) {
	env, ctx := testenv.New(t), context.Background()
	eng := env.Ctx(t, "engineer@rel.test")
	meta, _ := env.C.Blobs.Put(ctx, eng, randBytes(20_000), service.BlobInput{Marking: expt})
	raw, _ := os.ReadFile(env.ObjectPath(meta.ID))
	raw[len(raw)-100] ^= 0xFF
	_ = os.WriteFile(env.ObjectPath(meta.ID), raw, 0o600)
	_, _, err := env.C.Blobs.ReadAll(ctx, eng, meta.ID)
	wantCode(t, err, "integrity_violation")
	events, _ := env.C.Audit.List(ctx, 0, 1000)
	if last := events[len(events)-1]; last.Decision != "error" {
		t.Fatalf("integrity failure not audited: %+v", last)
	}
}

func TestMarkingDowngradeInDatabaseBreaksDecryption(t *testing.T) {
	env, ctx := testenv.New(t), context.Background()
	meta, _ := env.C.Blobs.Put(ctx, env.Ctx(t, "engineer@rel.test"), []byte("export controlled"), service.BlobInput{Marking: expt})
	if _, err := env.C.DB.Exec(ctx, `UPDATE blobs SET marking='UNCONTROLLED' WHERE id=$1`, meta.ID); err != nil {
		t.Fatal(err)
	}
	_, _, err := env.C.Blobs.ReadAll(ctx, env.Ctx(t, "admin@rel.test"), meta.ID)
	wantCode(t, err, "integrity_violation")
}

func TestForeignNationalCannotSeeExportControlled(t *testing.T) {
	env, ctx := testenv.New(t), context.Background()
	meta, _ := env.C.Blobs.Put(ctx, env.Ctx(t, "engineer@rel.test"), []byte("itar"), service.BlobInput{Marking: expt})
	foreign := env.Ctx(t, "foreign@rel.test")
	_, err := env.C.Blobs.Meta(ctx, foreign, meta.ID)
	wantCode(t, err, "not_found") // concealed: no existence oracle
	_, _, err = env.C.Blobs.ReadAll(ctx, foreign, meta.ID)
	wantCode(t, err, "not_found")
	items, _, _ := env.C.Blobs.List(ctx, foreign, 0, "")
	if len(items) != 0 {
		t.Fatal("listed a blob the caller may not see")
	}
	_, err = env.C.Blobs.Put(ctx, foreign, []byte("x"), service.BlobInput{Marking: expt})
	wantCode(t, err, "forbidden")
}

func TestShredIsIrreversible(t *testing.T) {
	env, ctx := testenv.New(t), context.Background()
	eng := env.Ctx(t, "engineer@rel.test")
	meta, _ := env.C.Blobs.Put(ctx, eng, []byte("to be destroyed"), service.BlobInput{Marking: expt})
	if err := env.C.Blobs.Delete(ctx, eng, meta.ID, true); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(env.ObjectPath(meta.ID)); !os.IsNotExist(err) {
		t.Fatal("object still on disk")
	}
	var state string
	var wrapped []byte
	_ = env.C.DB.QueryRow(ctx, `SELECT state, wrapped_dek FROM blobs WHERE id=$1`, meta.ID).Scan(&state, &wrapped)
	if state != "shredded" || wrapped != nil {
		t.Fatalf("state %s, wrapped key kept: %v", state, wrapped != nil)
	}
	_, _, err := env.C.Blobs.ReadAll(ctx, env.Ctx(t, "admin@rel.test"), meta.ID)
	wantCode(t, err, "not_found")
}

func TestSizeLimitAbortsAndCleansUp(t *testing.T) {
	env, ctx := testenv.New(t), context.Background()
	u, _, err := env.C.Blobs.Begin(ctx, env.Ctx(t, "engineer@rel.test"), service.BlobInput{Marking: expt, DeclaredSize: -1})
	if err != nil {
		t.Fatal(err)
	}
	for range 5 {
		if _, err := u.Write(randBytes(1024 * 1024)); err != nil {
			t.Fatal(err)
		}
	}
	_, err = u.Write([]byte("one byte too many"))
	wantCode(t, err, "payload_too_large")
	var n int
	_ = env.C.DB.QueryRow(ctx, `SELECT count(*) FROM blobs`).Scan(&n)
	files, _ := filepath.Glob(filepath.Join(env.BlobDir, "*", "*"))
	if n != 0 || len(files) != 0 {
		t.Fatalf("leftovers: %d rows, %v files", n, files)
	}
}

func TestIdempotentUploadAndValidation(t *testing.T) {
	env, ctx := testenv.New(t), context.Background()
	eng := env.Ctx(t, "engineer@rel.test")
	a, _ := env.C.Blobs.Put(ctx, eng, []byte("once"), service.BlobInput{Marking: expt, IdempotencyKey: "k-1"})
	b, _ := env.C.Blobs.Put(ctx, eng, []byte("once"), service.BlobInput{Marking: expt, IdempotencyKey: "k-1"})
	if a.ID != b.ID {
		t.Fatal("idempotent replay created a second blob")
	}
	_, err := env.C.Blobs.Put(ctx, eng, []byte("x"), service.BlobInput{Marking: expt, ContentType: "not a type"})
	wantCode(t, err, "validation_failed")
	_, err = env.C.Blobs.Put(ctx, eng, []byte("x"), service.BlobInput{Marking: expt, Filename: "../../etc/passwd"})
	wantCode(t, err, "validation_failed")
}

func TestListPagination(t *testing.T) {
	env, ctx := testenv.New(t), context.Background()
	eng := env.Ctx(t, "engineer@rel.test")
	ids := map[string]bool{}
	for range 5 {
		m, _ := env.C.Blobs.Put(ctx, eng, []byte("x"), service.BlobInput{Marking: expt})
		ids[m.ID] = true
	}
	seen := map[string]bool{}
	cur := ""
	for page := 0; page < 3; page++ {
		items, next, err := env.C.Blobs.List(ctx, eng, 2, cur)
		if err != nil {
			t.Fatal(err)
		}
		for _, m := range items {
			seen[m.ID] = true
		}
		cur = next
	}
	if len(seen) != 5 || cur != "" {
		t.Fatalf("pagination saw %d, cursor %q", len(seen), cur)
	}
	for id := range ids {
		if !seen[id] {
			t.Fatal("missing blob in pages")
		}
	}
}

func TestAgentSeesMetadataNotCUIContent(t *testing.T) {
	env, ctx := testenv.New(t), context.Background()
	meta, _ := env.C.Blobs.Put(ctx, env.Ctx(t, "engineer@rel.test"), []byte("cui"), service.BlobInput{Marking: expt})
	agent := env.Ctx(t, "agent:assistant")
	if _, err := env.C.Blobs.Meta(ctx, agent, meta.ID); err != nil {
		t.Fatal(err)
	}
	_, _, err := env.C.Blobs.ReadAll(ctx, agent, meta.ID)
	wantCode(t, err, "content_withheld")
	_, body, err := env.C.Blobs.ReadAll(ctx, env.Ctx(t, "agent:boundary"), meta.ID)
	if err != nil || string(body) != "cui" {
		t.Fatalf("cleared agent: %v", err)
	}
}
