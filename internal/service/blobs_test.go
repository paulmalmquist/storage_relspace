package service_test

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/paulmalmquist/storage_relspace/internal/service"
	"github.com/paulmalmquist/storage_relspace/internal/testenv"
)

func sharedBlob(m service.BlobInput) service.BlobInput { m.Visibility = "app"; return m }

func TestBlobRoundTrip(t *testing.T) {
	env, ctx := testenv.New(t), context.Background()
	eng := env.Ctx(t, "engineer@rel.test")
	data := randBytes(1_000_003)
	meta, err := env.C.Blobs.Put(ctx, eng, data, service.BlobInput{Marking: expt, Filename: "weld-map.bin",
		Metadata: map[string]any{"part_number": "TR-1042", "lot": 7}})
	if err != nil {
		t.Fatal(err)
	}
	if *meta.SizeBytes != int64(len(data)) || meta.Owner != "engineer@rel.test" || meta.Visibility != "private" {
		t.Fatalf("meta %+v", meta)
	}
	got, body, err := env.C.Blobs.ReadAll(ctx, eng, meta.ID)
	if err != nil || !bytes.Equal(body, data) {
		t.Fatalf("round trip: %v", err)
	}
	if got.Filename != "weld-map.bin" || got.Metadata["part_number"] != "TR-1042" || !got.Marking.Equal(expt) {
		t.Fatalf("metadata %+v", got)
	}
	// Object addresses carry the app boundary.
	if p := env.ObjectPath(t, meta.ID); !bytes.Contains([]byte(filepath.ToSlash(p)), []byte("apps/acme/test/"+meta.ID+"/")) {
		t.Fatalf("object path %s is not under the app prefix", p)
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
	disk, _ := os.ReadFile(env.ObjectPath(t, meta.ID))
	if bytes.Contains(disk, []byte("INJECTOR")) {
		t.Fatal("plaintext on disk")
	}
	var sealed, wrapped []byte
	if err := env.Migrator.QueryRow(ctx, `SELECT sealed_meta, wrapped_dek FROM blobs WHERE id=$1`, meta.ID).Scan(&sealed, &wrapped); err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(sealed, []byte("pintle")) || bytes.Contains(sealed, []byte("HOTFIRE")) || len(wrapped) <= 32 {
		t.Fatal("metadata or key not protected")
	}
}

func TestTamperedObjectDetectedAndAudited(t *testing.T) {
	env, ctx := testenv.New(t), context.Background()
	eng := env.Ctx(t, "engineer@rel.test")
	meta := must[*service.BlobMeta](t)(env.C.Blobs.Put(ctx, eng, randBytes(20_000), service.BlobInput{Marking: expt}))
	raw, _ := os.ReadFile(env.ObjectPath(t, meta.ID))
	raw[len(raw)-100] ^= 0xFF
	_ = os.WriteFile(env.ObjectPath(t, meta.ID), raw, 0o600)
	_, _, err := env.C.Blobs.ReadAll(ctx, eng, meta.ID)
	wantCode(t, err, "integrity_violation")
	var n int
	_ = env.Migrator.QueryRow(ctx, `SELECT count(*) FROM audit_events WHERE resource_id=$1 AND decision='error'
		AND reason LIKE 'integrity failure%'`, meta.ID).Scan(&n)
	if n != 1 {
		t.Fatalf("integrity failure audited %d times", n)
	}
}

func TestMarkingDowngradeInDatabaseBreaksDecryption(t *testing.T) {
	env, ctx := testenv.New(t), context.Background()
	meta := must[*service.BlobMeta](t)(env.C.Blobs.Put(ctx, env.Ctx(t, "engineer@rel.test"), []byte("export controlled"),
		sharedBlob(service.BlobInput{Marking: expt})))
	env.Admin(t, `UPDATE blobs SET marking='UNCONTROLLED' WHERE id=$1`, meta.ID)
	_, _, err := env.C.Blobs.ReadAll(ctx, env.Ctx(t, "admin@rel.test"), meta.ID)
	wantCode(t, err, "integrity_violation")
}

func TestForeignNationalCannotSeeExportControlled(t *testing.T) {
	env, ctx := testenv.New(t), context.Background()
	meta := must[*service.BlobMeta](t)(env.C.Blobs.Put(ctx, env.Ctx(t, "engineer@rel.test"), []byte("itar"),
		sharedBlob(service.BlobInput{Marking: expt})))
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

func TestShredDestroysKeyAndWorkerDeletesObject(t *testing.T) {
	env, ctx := testenv.New(t), context.Background()
	eng := env.Ctx(t, "engineer@rel.test")
	meta := must[*service.BlobMeta](t)(env.C.Blobs.Put(ctx, eng, []byte("to be destroyed"), service.BlobInput{Marking: expt}))
	path := env.ObjectPath(t, meta.ID)
	if err := env.C.Blobs.Delete(ctx, eng, meta.ID, true); err != nil {
		t.Fatal(err)
	}
	var state string
	var wrapped []byte
	_ = env.Migrator.QueryRow(ctx, `SELECT state, wrapped_dek FROM blobs WHERE id=$1`, meta.ID).Scan(&state, &wrapped)
	if state != "shredded" || wrapped != nil {
		t.Fatalf("state %s, wrapped key kept: %v", state, wrapped != nil)
	}
	_, _, err := env.C.Blobs.ReadAll(ctx, eng, meta.ID)
	wantCode(t, err, "not_found")
	if _, err := os.Stat(path); err != nil {
		t.Fatal("object deleted before the worker ran (deletion must go through the outbox)")
	}
	stats, err := env.C.Worker.RunOnce(ctx)
	if err != nil || stats.JobsDone != 1 {
		t.Fatalf("worker: %v %+v", err, stats)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatal("object still on disk after the worker ran")
	}
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
	var state string
	_ = env.Migrator.QueryRow(ctx, `SELECT state FROM blobs`).Scan(&state)
	if _, err := env.C.Worker.RunOnce(ctx); err != nil {
		t.Fatal(err)
	}
	files, _ := filepath.Glob(filepath.Join(env.BlobDir, "apps", "*", "*", "*", "*"))
	if state != "aborted" || len(files) != 0 {
		t.Fatalf("leftovers: state %s, files %v", state, files)
	}
}

func TestUploadValidation(t *testing.T) {
	env, ctx := testenv.New(t), context.Background()
	eng := env.Ctx(t, "engineer@rel.test")
	_, err := env.C.Blobs.Put(ctx, eng, []byte("x"), service.BlobInput{Marking: expt, ContentType: "not a type"})
	wantCode(t, err, "validation_failed")
	_, err = env.C.Blobs.Put(ctx, eng, []byte("x"), service.BlobInput{Marking: expt, Filename: "../../etc/passwd"})
	wantCode(t, err, "validation_failed")
	_, err = env.C.Blobs.Put(ctx, env.Ctx(t, "intern@rel.test"), []byte("x"), service.BlobInput{})
	wantCode(t, err, "forbidden") // viewer role
}

func TestListPagination(t *testing.T) {
	env, ctx := testenv.New(t), context.Background()
	eng := env.Ctx(t, "engineer@rel.test")
	ids := map[string]bool{}
	for range 5 {
		m := must[*service.BlobMeta](t)(env.C.Blobs.Put(ctx, eng, []byte("x"), service.BlobInput{Marking: expt}))
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
}

// Records the caller may not see are excluded before LIMIT: the page is full and the cursor does
// not hint at hidden rows.
func TestHiddenRowsDoNotShapePages(t *testing.T) {
	env, ctx := testenv.New(t), context.Background()
	eng := env.Ctx(t, "engineer@rel.test")
	for range 3 {
		must[*service.BlobMeta](t)(env.C.Blobs.Put(ctx, eng, []byte("x"), sharedBlob(service.BlobInput{Marking: expt})))
	}
	must[*service.BlobMeta](t)(env.C.Blobs.Put(ctx, eng, []byte("y"), sharedBlob(service.BlobInput{})))
	foreign := env.Ctx(t, "foreign@rel.test") // not a U.S. person: NOFORN is hidden
	items, next, err := env.C.Blobs.List(ctx, foreign, 1, "")
	if err != nil || len(items) != 1 || next != "" {
		t.Fatalf("foreign: %d items, next %q, %v", len(items), next, err)
	}
}

func TestAgentSeesMetadataNotCUIContent(t *testing.T) {
	env, ctx := testenv.New(t), context.Background()
	meta := must[*service.BlobMeta](t)(env.C.Blobs.Put(ctx, env.Ctx(t, "engineer@rel.test"), []byte("cui"),
		sharedBlob(service.BlobInput{Marking: expt})))
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

// Finding 4: a sweep racing an in-progress upload. Exactly one side wins: the sweeper cannot abort
// a leased upload, and once it has aborted an expired one, the late commit fails and leaves neither
// an object nor a "stored" audit event.
func TestUploadSweepAndCommitRace(t *testing.T) {
	env, ctx := testenv.New(t), context.Background()
	eng := env.Ctx(t, "engineer@rel.test")
	u, _, err := env.C.Blobs.Begin(ctx, eng, service.BlobInput{Marking: expt, DeclaredSize: -1})
	if err != nil {
		t.Fatal(err)
	}
	_, _ = u.Write([]byte("in flight"))
	stats, _ := env.C.Worker.RunOnce(ctx)
	if stats.UploadsAborted != 0 {
		t.Fatal("sweeper aborted an upload that holds its lease")
	}
	env.Admin(t, `UPDATE blobs SET lease_expires = now() - interval '1 second' WHERE id = $1`, u.ID)
	if stats, _ := env.C.Worker.RunOnce(ctx); stats.UploadsAborted != 1 {
		t.Fatalf("expired upload not swept: %+v", stats)
	}
	_, err = u.Commit()
	wantCode(t, err, "upload_expired")
	if _, err := env.C.Worker.RunOnce(ctx); err != nil {
		t.Fatal(err)
	}
	files, _ := filepath.Glob(filepath.Join(env.BlobDir, "apps", "*", "*", "*", "*"))
	var stored int
	_ = env.Migrator.QueryRow(ctx, `SELECT count(*) FROM audit_events WHERE resource_id=$1 AND reason='blob stored'`, u.ID).Scan(&stored)
	var state string
	_ = env.Migrator.QueryRow(ctx, `SELECT state FROM blobs WHERE id=$1`, u.ID).Scan(&state)
	if len(files) != 0 || stored != 0 || (state != "aborted" && state != "purged") {
		t.Fatalf("files %v, stored events %d, state %s", files, stored, state)
	}
}

// Finding 5: concurrent uploads with one operation ID produce one canonical blob; the second
// attempt is told the operation is in progress, and a retry after completion with different
// content is rejected.
func TestConcurrentUploadsWithOneOperationID(t *testing.T) {
	env, ctx := testenv.New(t), context.Background()
	eng := env.Ctx(t, "engineer@rel.test")
	eng.OpID = "upload-op-0001"
	a, _, errA := env.C.Blobs.Begin(ctx, eng, service.BlobInput{Marking: expt, DeclaredSize: 3})
	_, _, errB := env.C.Blobs.Begin(ctx, eng, service.BlobInput{Marking: expt, DeclaredSize: 3})
	if errA != nil {
		t.Fatal(errA)
	}
	wantCode(t, errB, "operation_in_progress")
	_, _ = a.Write([]byte("one"))
	first := must[*service.BlobMeta](t)(a.Commit())
	again := must[*service.BlobMeta](t)(env.C.Blobs.Put(ctx, eng, []byte("one"), service.BlobInput{Marking: expt}))
	if again.ID != first.ID || !again.Replayed {
		t.Fatal("retry did not return the canonical blob")
	}
	_, err := env.C.Blobs.Put(ctx, eng, []byte("two"), service.BlobInput{Marking: expt})
	wantCode(t, err, "idempotency_key_reused")
	_, err = env.C.Blobs.Put(ctx, eng, []byte("one"), service.BlobInput{Marking: expt, Filename: "renamed"})
	wantCode(t, err, "idempotency_key_reused")
	var active int
	_ = env.Migrator.QueryRow(ctx, `SELECT count(*) FROM blobs WHERE state='active'`).Scan(&active)
	if active != 1 {
		t.Fatalf("%d active blobs", active)
	}
}

// Many goroutines race the same operation ID; exactly one upload happens.
func TestConcurrentPutsConverge(t *testing.T) {
	env, ctx := testenv.New(t), context.Background()
	eng := env.Ctx(t, "engineer@rel.test")
	eng.OpID = "upload-op-race"
	var wg sync.WaitGroup
	ids := make(chan string, 8)
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for attempt := 0; attempt < 50; attempt++ {
				m, err := env.C.Blobs.Put(ctx, eng, []byte("same"), service.BlobInput{Marking: expt})
				if err == nil {
					ids <- m.ID
					return
				}
				time.Sleep(20 * time.Millisecond) // operation_in_progress: retry
			}
		}()
	}
	wg.Wait()
	close(ids)
	seen := map[string]bool{}
	for id := range ids {
		seen[id] = true
	}
	if len(seen) != 1 {
		t.Fatalf("one operation ID produced %d blobs", len(seen))
	}
}

// A crashed upload's operation can be taken over once its lease expires.
func TestExpiredUploadLeaseIsTakenOver(t *testing.T) {
	env, ctx := testenv.New(t), context.Background()
	eng := env.Ctx(t, "engineer@rel.test")
	eng.OpID = "upload-op-crash"
	crashed, _, err := env.C.Blobs.Begin(ctx, eng, service.BlobInput{Marking: expt, DeclaredSize: 4})
	if err != nil {
		t.Fatal(err)
	}
	_, _ = crashed.Write([]byte("hal"))
	env.Admin(t, `UPDATE operation_receipts SET lease_expires = now() - interval '1 second'`)
	m, err := env.C.Blobs.Put(ctx, eng, []byte("full"), service.BlobInput{Marking: expt})
	if err != nil {
		t.Fatal(err)
	}
	_, err = crashed.Commit()
	wantCode(t, err, "upload_expired")
	_, body, err := env.C.Blobs.ReadAll(ctx, env.Ctx(t, "engineer@rel.test"), m.ID)
	if err != nil || string(body) != "full" {
		t.Fatalf("takeover upload: %v %q", err, body)
	}
}
