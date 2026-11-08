package backup_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/paulmalmquist/storage_relspace/internal/admin"
	"github.com/paulmalmquist/storage_relspace/internal/audit"
	"github.com/paulmalmquist/storage_relspace/internal/backup"
	"github.com/paulmalmquist/storage_relspace/internal/markings"
	"github.com/paulmalmquist/storage_relspace/internal/service"
	"github.com/paulmalmquist/storage_relspace/internal/testenv"
)

func randBytes(n int) []byte {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return b
}

// A synthetic app is exported, validated offline, dry-run restored (which leaves the target
// empty), restored into a separate database, and then read back through the service with the
// same keys: records, history, sharing, blobs (single and multipart), audit chains and usage.
func TestExportValidateRestore(t *testing.T) {
	ctx := context.Background()
	src := testenv.New(t)
	adm, eng := src.Ctx(t, "admin@rel.test"), src.Ctx(t, "engineer@rel.test")
	expt := markings.MustParse("CUI//SP-EXPT")
	if _, err := src.C.Records.CreateCollection(ctx, adm, service.CollectionInput{Name: "parts", Marking: expt,
		IndexedFields: []string{"sku"}, UniqueFields: []string{"sku"}}); err != nil {
		t.Fatal(err)
	}
	var ids []string
	for i := range 30 {
		r, err := src.C.Records.Create(ctx, eng, "parts", service.RecordInput{Data: map[string]any{"sku": string(rune('A'+i%26)) + strings.Repeat("x", i)}})
		if err != nil {
			t.Fatal(err)
		}
		ids = append(ids, r.ID)
	}
	if _, err := src.C.Records.Update(ctx, eng, "parts", ids[0], service.RecordInput{Data: map[string]any{"sku": "changed"}}, 1); err != nil {
		t.Fatal(err)
	}
	if err := src.C.Records.Delete(ctx, eng, "parts", ids[1], nil, false); err != nil {
		t.Fatal(err)
	}
	if _, err := src.C.Sharing.AddGrant(ctx, eng, service.ResourceRef{Kind: "record", Collection: "parts", ID: ids[2]}, service.GrantInput{Subject: "teammate@rel.test", Role: "viewer"}); err != nil {
		t.Fatal(err)
	}
	small := randBytes(70_000)
	b1, err := src.C.Blobs.Put(ctx, eng, small, service.BlobInput{Marking: expt, Filename: "a.bin"})
	if err != nil {
		t.Fatal(err)
	}
	big := randBytes(3*16384 + 77)
	sess, err := src.C.Blobs.CreateSession(ctx, eng, service.BlobInput{Marking: expt, DeclaredSize: int64(len(big))})
	if err != nil {
		t.Fatal(err)
	}
	for n := 1; n <= sess.PartCount; n++ {
		start := (n - 1) * 16384
		if _, err := src.C.Blobs.PutPart(ctx, eng, sess.ID, n, bytes.NewReader(big[start:min(start+16384, len(big))])); err != nil {
			t.Fatal(err)
		}
	}
	b2, err := src.C.Blobs.CompleteSession(ctx, eng, sess.ID)
	if err != nil {
		t.Fatal(err)
	}
	// Another app's data must not leak into the export.
	if _, err := src.C.Records.CreateCollection(ctx, src.CtxIn(t, testenv.Other, "admin@rel.test"),
		service.CollectionInput{Name: "secret", Marking: expt}); err != nil {
		t.Fatal(err)
	}

	dir := filepath.Join(t.TempDir(), "export")
	m, err := backup.Export(ctx, src.Migrator, src.C.Backend, testenv.App, dir, "test", "test-build")
	if err != nil {
		t.Fatal(err)
	}
	if m.Objects.Count != 1+int64(sess.PartCount) {
		t.Fatalf("exported %d objects", m.Objects.Count)
	}
	for _, e := range m.Tables {
		raw, _ := os.ReadFile(filepath.Join(dir, e.File))
		if bytes.Contains(raw, []byte(testenv.Other)) || bytes.Contains(raw, []byte(`"secret"`)) {
			t.Fatalf("%s contains another app's rows", e.File)
		}
		if bytes.Contains(raw, []byte("changed")) {
			t.Fatalf("%s contains record plaintext", e.File)
		}
	}
	if _, rep, err := backup.Validate(dir); err != nil || !rep.OK() {
		t.Fatalf("validate: %v %+v", err, rep)
	}

	dst := testenv.EmptyDatabase(t, src.Keyring)
	// Restoring into the source itself is refused.
	if _, err := backup.Restore(ctx, src.Migrator, src.C.Backend, dir, true); err == nil {
		t.Fatal("restore into the source database was accepted")
	}
	dry, err := backup.Restore(ctx, dst.Migrator, dst.C.Backend, dir, true)
	if err != nil {
		t.Fatalf("dry run: %v", err)
	}
	if dry.Rows["records"] != 30 || dry.Objects != 0 {
		t.Fatalf("dry run report %+v", dry)
	}
	var apps int
	_ = dst.Migrator.QueryRow(ctx, `SELECT count(*) FROM apps`).Scan(&apps)
	if apps != 1 { // only _legacy
		t.Fatalf("dry run left %d apps", apps)
	}
	if _, err := backup.Restore(ctx, dst.Migrator, dst.C.Backend, dir, false); err != nil {
		t.Fatal(err)
	}
	if _, err := backup.Restore(ctx, dst.Migrator, dst.C.Backend, dir, false); err == nil {
		t.Fatal("a second restore of the same app was accepted")
	}

	// Read back through the service, as the same users, with the same keys.
	dEng, dMate := dst.Ctx(t, "engineer@rel.test"), dst.Ctx(t, "teammate@rel.test")
	got, err := dst.C.Records.Get(ctx, dEng, "parts", ids[0])
	if err != nil || got.Data["sku"] != "changed" || got.Version != 2 {
		t.Fatalf("restored record %+v %v", got, err)
	}
	if hist, _, err := dst.C.Records.History(ctx, dEng, "parts", ids[0], 0, 0); err != nil || len(hist) != 2 {
		t.Fatalf("history %v %v", hist, err)
	}
	if _, err := dst.C.Records.Restore(ctx, dEng, "parts", ids[1], 1, 2); err != nil {
		t.Fatalf("undo a delete after restore: %v", err)
	}
	if _, err := dst.C.Records.Get(ctx, dMate, "parts", ids[2]); err != nil {
		t.Fatalf("grant not restored: %v", err)
	}
	if _, err := dst.C.Records.Create(ctx, dEng, "parts", service.RecordInput{Data: map[string]any{"sku": "changed"}}); !strings.Contains(errString(err), "unique") {
		t.Fatalf("uniqueness not restored: %v", err)
	}
	for blob, want := range map[string][]byte{b1.ID: small, b2.ID: big} {
		_, body, err := dst.C.Blobs.ReadAll(ctx, dEng, blob)
		if err != nil || !bytes.Equal(body, want) {
			t.Fatalf("blob %s: %v", blob, err)
		}
	}
	v, err := dst.C.VerifyApp(ctx, testenv.App, true)
	if err != nil || len(v.Problems) != 0 || v.Records != 30 || v.Blobs != 2 {
		t.Fatalf("verify %+v %v", v, err)
	}
	a := &admin.Admin{Pool: dst.Migrator, Actor: "test", Stripes: 4}
	u, err := a.AppUsage(ctx, testenv.App, true, false)
	if err != nil || u.Drift || u.Blobs != 2 {
		t.Fatalf("usage %+v %v", u, err)
	}
	tx, err := dst.Migrator.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	res, err := audit.New(nil, 4).Verify(ctx, tx)
	if err != nil || !res.OK {
		t.Fatalf("audit chains after restore: %+v %v", res, err)
	}
}

func TestValidateDetectsTampering(t *testing.T) {
	ctx := context.Background()
	src := testenv.New(t)
	eng := src.Ctx(t, "engineer@rel.test")
	b, err := src.C.Blobs.Put(ctx, eng, randBytes(5000), service.BlobInput{Marking: markings.MustParse("CUI//SP-EXPT")})
	if err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(t.TempDir(), "export")
	if _, err := backup.Export(ctx, src.Migrator, src.C.Backend, testenv.App, dir, "test", "test-build"); err != nil {
		t.Fatal(err)
	}
	var key string
	_ = src.Migrator.QueryRow(ctx, `SELECT storage_key FROM blobs WHERE id = $1`, b.ID).Scan(&key)
	obj := filepath.Join(dir, "objects", filepath.FromSlash(key))
	raw, _ := os.ReadFile(obj)
	raw[50] ^= 1
	_ = os.WriteFile(obj, raw, 0o600)
	tbl := filepath.Join(dir, "tables", "app_members.ndjson")
	f, _ := os.OpenFile(tbl, os.O_APPEND|os.O_WRONLY, 0)
	_, _ = f.WriteString(`{"app":"acme:test","subject":"mallory@rel.test","role":"admin"}` + "\n")
	_ = f.Close()
	_, rep, err := backup.Validate(dir)
	if err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(rep.Problems, "\n")
	if !strings.Contains(joined, "app_members.ndjson: digest mismatch") || !strings.Contains(joined, "size or digest mismatch") {
		t.Fatalf("problems: %s", joined)
	}
	dst := testenv.EmptyDatabase(t, src.Keyring)
	if _, err := backup.Restore(ctx, dst.Migrator, dst.C.Backend, dir, false); err == nil {
		t.Fatal("a tampered export was restored")
	}
}

func errString(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}
