package service_test

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/paulmalmquist/storage_relspace/internal/admin"
	"github.com/paulmalmquist/storage_relspace/internal/service"
	"github.com/paulmalmquist/storage_relspace/internal/testenv"
)

const partSize = 16384 // testenv STRONGBOX_UPLOAD_PART_BYTES

func putParts(t *testing.T, env *testenv.Env, c service.Ctx, id string, data []byte, order []int) {
	t.Helper()
	ctx := context.Background()
	for _, n := range order {
		start := (n - 1) * partSize
		end := min(start+partSize, len(data))
		if _, err := env.C.Blobs.PutPart(ctx, c, id, n, bytes.NewReader(data[start:end])); err != nil {
			t.Fatalf("part %d: %v", n, err)
		}
	}
}

func TestUploadSessionRoundTrip(t *testing.T) {
	env, ctx := testenv.New(t), context.Background()
	eng := env.Ctx(t, "engineer@rel.test")
	data := randBytes(3*partSize + 1234) // four parts, the last one short
	sess, err := env.C.Blobs.CreateSession(ctx, eng, service.BlobInput{Marking: expt, Filename: "big.bin", DeclaredSize: int64(len(data))})
	if err != nil {
		t.Fatal(err)
	}
	if sess.PartCount != 4 || sess.PartSize != partSize {
		t.Fatalf("session %+v", sess)
	}
	// Parts arrive out of order; part 2 is sent twice (a retry) and replaces the first copy.
	putParts(t, env, eng, sess.ID, data, []int{4, 2, 1, 2})
	_, err = env.C.Blobs.CompleteSession(ctx, eng, sess.ID)
	wantCode(t, err, "upload_incomplete")

	// Exact sizes: a short non-final part and an oversized last part are refused.
	_, err = env.C.Blobs.PutPart(ctx, eng, sess.ID, 3, bytes.NewReader(data[:partSize-1]))
	wantCode(t, err, "validation_failed")
	_, err = env.C.Blobs.PutPart(ctx, eng, sess.ID, 4, bytes.NewReader(data[:2000]))
	wantCode(t, err, "validation_failed")
	_, err = env.C.Blobs.PutPart(ctx, eng, sess.ID, 5, bytes.NewReader(nil))
	wantCode(t, err, "validation_failed")

	// Sessions belong to their uploader.
	_, err = env.C.Blobs.PutPart(ctx, env.Ctx(t, "admin@rel.test"), sess.ID, 3, bytes.NewReader(data[2*partSize:3*partSize]))
	wantCode(t, err, "not_found")

	got, err := env.C.Blobs.Session(ctx, eng, sess.ID)
	if err != nil || len(got.Received) != 3 {
		t.Fatalf("resume state %+v %v", got, err)
	}
	putParts(t, env, eng, sess.ID, data, []int{3})
	meta, err := env.C.Blobs.CompleteSession(ctx, eng, sess.ID)
	if err != nil {
		t.Fatal(err)
	}
	if *meta.SizeBytes != int64(len(data)) || meta.Filename != "big.bin" {
		t.Fatalf("meta %+v", meta)
	}
	_, body, err := env.C.Blobs.ReadAll(ctx, eng, meta.ID)
	if err != nil || !bytes.Equal(body, data) {
		t.Fatalf("read back: %v", err)
	}
	// Completing twice returns the same blob.
	if again, err := env.C.Blobs.CompleteSession(ctx, eng, sess.ID); err != nil || again.ID != meta.ID {
		t.Fatalf("second complete: %v", err)
	}
	// The replaced copy of part 2 is deleted by the worker; four part objects remain.
	if _, err := env.C.Worker.RunOnce(ctx); err != nil {
		t.Fatal(err)
	}
	files, _ := filepath.Glob(filepath.Join(env.BlobDir, "apps", "acme", "test", meta.ID, "*", "p*"))
	if len(files) != 4 {
		t.Fatalf("%d part objects on disk, want 4: %v", len(files), files)
	}

	// Tampering with a part is detected and audited.
	raw := files[1]
	b := must[[]byte](t)(os.ReadFile(raw))
	b[100] ^= 0xFF
	if err := os.WriteFile(raw, b, 0o600); err != nil {
		t.Fatal(err)
	}
	_, _, err = env.C.Blobs.ReadAll(ctx, eng, meta.ID)
	wantCode(t, err, "integrity_violation")

	// Deleting the blob removes every part.
	if err := env.C.Blobs.Delete(ctx, eng, meta.ID, false); err != nil {
		t.Fatal(err)
	}
	if _, err := env.C.Worker.RunOnce(ctx); err != nil {
		t.Fatal(err)
	}
	files, _ = filepath.Glob(filepath.Join(env.BlobDir, "apps", "acme", "test", meta.ID, "*", "p*"))
	if len(files) != 0 {
		t.Fatalf("parts left after delete: %v", files)
	}
	var state string
	var dek []byte
	_ = env.Migrator.QueryRow(ctx, `SELECT state, wrapped_dek FROM blobs WHERE id = $1`, meta.ID).Scan(&state, &dek)
	if state != "purged" || dek != nil {
		t.Fatalf("after purge: state %s, wrapped key kept: %v", state, dek != nil)
	}
}

func TestEmptyAndAbortedSessions(t *testing.T) {
	env, ctx := testenv.New(t), context.Background()
	eng := env.Ctx(t, "engineer@rel.test")
	empty := must[*service.UploadSession](t)(env.C.Blobs.CreateSession(ctx, eng, service.BlobInput{Marking: expt, DeclaredSize: 0}))
	if empty.PartCount != 1 {
		t.Fatalf("empty blob has %d parts", empty.PartCount)
	}
	putParts(t, env, eng, empty.ID, nil, []int{1})
	meta := must[*service.BlobMeta](t)(env.C.Blobs.CompleteSession(ctx, eng, empty.ID))
	if _, body, err := env.C.Blobs.ReadAll(ctx, eng, meta.ID); err != nil || len(body) != 0 {
		t.Fatalf("empty blob: %v %d", err, len(body))
	}

	data := randBytes(2 * partSize)
	sess := must[*service.UploadSession](t)(env.C.Blobs.CreateSession(ctx, eng, service.BlobInput{Marking: expt, DeclaredSize: int64(len(data))}))
	putParts(t, env, eng, sess.ID, data, []int{1})
	if err := env.C.Blobs.AbortSession(ctx, eng, sess.ID); err != nil {
		t.Fatal(err)
	}
	_, err := env.C.Blobs.PutPart(ctx, eng, sess.ID, 2, bytes.NewReader(data[partSize:]))
	wantCode(t, err, "upload_expired")
	_, err = env.C.Blobs.CompleteSession(ctx, eng, sess.ID)
	wantCode(t, err, "upload_expired")
	if _, err := env.C.Worker.RunOnce(ctx); err != nil {
		t.Fatal(err)
	}
	files, _ := filepath.Glob(filepath.Join(env.BlobDir, "apps", "acme", "test", sess.ID, "*", "p*"))
	if len(files) != 0 {
		t.Fatalf("aborted parts left: %v", files)
	}
	// Too large for any blob.
	_, err = env.C.Blobs.CreateSession(ctx, eng, service.BlobInput{Marking: expt, DeclaredSize: 9 << 20})
	wantCode(t, err, "payload_too_large")
}

func quotas(t *testing.T, env *testenv.Env, q admin.Quota) {
	t.Helper()
	a := &admin.Admin{Pool: env.Migrator, Actor: "test-admin", Stripes: 4}
	if err := a.SetQuota(context.Background(), testenv.App, q); err != nil {
		t.Fatal(err)
	}
}

func ptr(v int64) *int64 { return &v }

func TestBlobQuotaIsExactUnderConcurrency(t *testing.T) {
	env, ctx := testenv.New(t), context.Background()
	quotas(t, env, admin.Quota{MaxBlobBytes: ptr(100_000)})
	eng := env.Ctx(t, "engineer@rel.test")
	var wg sync.WaitGroup
	var mu sync.Mutex
	ok, refused := 0, 0
	for range 12 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := env.C.Blobs.Put(ctx, eng, randBytes(30_000), service.BlobInput{Marking: expt})
			mu.Lock()
			defer mu.Unlock()
			switch {
			case err == nil:
				ok++
			case strings.Contains(err.Error(), "max_blob_bytes"):
				refused++
			default:
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	if ok != 3 || refused != 9 {
		t.Fatalf("%d stored, %d refused; want exactly 3 stored under a 100 kB quota", ok, refused)
	}
	u := must[*service.AppUsage](t)(env.C.Sharing.Usage(ctx, eng))
	if u.BlobBytes != 90_000 || u.Blobs != 3 || u.ReservedBytes != 0 {
		t.Fatalf("usage %+v", u)
	}
	// A session reserves its declared size up front, and aborting releases it.
	_, err := env.C.Blobs.CreateSession(ctx, eng, service.BlobInput{Marking: expt, DeclaredSize: 20_000})
	wantCode(t, err, "quota_exceeded")
	sess := must[*service.UploadSession](t)(env.C.Blobs.CreateSession(ctx, eng, service.BlobInput{Marking: expt, DeclaredSize: 10_000}))
	if u := must[*service.AppUsage](t)(env.C.Sharing.Usage(ctx, eng)); u.ReservedBytes != 10_000 {
		t.Fatalf("reservation not counted: %+v", u)
	}
	if err := env.C.Blobs.AbortSession(ctx, eng, sess.ID); err != nil {
		t.Fatal(err)
	}
	if u := must[*service.AppUsage](t)(env.C.Sharing.Usage(ctx, eng)); u.ReservedBytes != 0 {
		t.Fatalf("reservation not released: %+v", u)
	}
	// Deleting frees space.
	items, _, _ := env.C.Blobs.List(ctx, eng, 10, "")
	if err := env.C.Blobs.Delete(ctx, eng, items[0].ID, false); err != nil {
		t.Fatal(err)
	}
	if _, err := env.C.Blobs.Put(ctx, eng, randBytes(30_000), service.BlobInput{Marking: expt}); err != nil {
		t.Fatalf("after delete: %v", err)
	}
}

func TestRecordQuotaAndUsageAccounting(t *testing.T) {
	env, ctx := testenv.New(t), context.Background()
	eng := env.Ctx(t, "engineer@rel.test")
	adminCtx := env.Ctx(t, "admin@rel.test")
	if _, err := env.C.Records.CreateCollection(ctx, adminCtx, service.CollectionInput{Name: "notes", Marking: cuiExpt}); err != nil {
		t.Fatal(err)
	}
	quotas(t, env, admin.Quota{MaxRecords: ptr(3)})
	var ids []string
	for i := range 3 {
		rec, err := env.C.Records.Create(ctx, eng, "notes", service.RecordInput{Data: map[string]any{"n": i}})
		if err != nil {
			t.Fatal(err)
		}
		ids = append(ids, rec.ID)
	}
	_, err := env.C.Records.Create(ctx, eng, "notes", service.RecordInput{Data: map[string]any{"n": 4}})
	wantCode(t, err, "quota_exceeded")
	// Updates within the count limit are fine; deleting frees a slot; undo of a delete needs one.
	if _, err := env.C.Records.Update(ctx, eng, "notes", ids[0], service.RecordInput{Data: map[string]any{"n": "longer value"}}, 1); err != nil {
		t.Fatal(err)
	}
	if err := env.C.Records.Delete(ctx, eng, "notes", ids[1], nil, false); err != nil {
		t.Fatal(err)
	}
	if _, err := env.C.Records.Create(ctx, eng, "notes", service.RecordInput{Data: map[string]any{"n": 5}}); err != nil {
		t.Fatalf("after delete: %v", err)
	}
	_, err = env.C.Records.Restore(ctx, eng, "notes", ids[1], 1, 2)
	wantCode(t, err, "quota_exceeded")

	// Counters equal a full recount after creates, updates, deletes and refused writes.
	a := &admin.Admin{Pool: env.Migrator, Actor: "test-admin", Stripes: 4}
	u, err := a.AppUsage(ctx, testenv.App, true, false)
	if err != nil {
		t.Fatal(err)
	}
	if u.Drift || u.Records != 3 || u.RecordBytes == 0 || u.Recount.RecordBytes != u.RecordBytes {
		t.Fatalf("usage %+v recount %+v", u, u.Recount)
	}
	quotas(t, env, admin.Quota{MaxRecordBytes: ptr(u.RecordBytes + 10)})
	_, err = env.C.Records.Update(ctx, eng, "notes", ids[0], service.RecordInput{Data: map[string]any{"n": strings.Repeat("x", 200)}}, 2)
	wantCode(t, err, "quota_exceeded")
	// Shrinking is always allowed.
	if _, err := env.C.Records.Update(ctx, eng, "notes", ids[0], service.RecordInput{Data: map[string]any{}}, 2); err != nil {
		t.Fatalf("shrinking update: %v", err)
	}
}

func TestDeletedRecordsExpireWithTheirHistory(t *testing.T) {
	env, ctx := testenv.New(t), context.Background()
	eng := env.Ctx(t, "engineer@rel.test")
	if _, err := env.C.Records.CreateCollection(ctx, env.Ctx(t, "admin@rel.test"), service.CollectionInput{Name: "notes", Marking: cuiExpt}); err != nil {
		t.Fatal(err)
	}
	old := must[*service.Record](t)(env.C.Records.Create(ctx, eng, "notes", service.RecordInput{Data: map[string]any{"v": 1}}))
	recent := must[*service.Record](t)(env.C.Records.Create(ctx, eng, "notes", service.RecordInput{Data: map[string]any{"v": 2}}))
	for _, id := range []string{old.ID, recent.ID} {
		if err := env.C.Records.Delete(ctx, eng, "notes", id, nil, false); err != nil {
			t.Fatal(err)
		}
	}
	env.Admin(t, `UPDATE records SET deleted_at = now() - interval '31 days' WHERE id = $1`, old.ID)
	stats, err := env.C.Worker.RunOnce(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if stats.RecordsPurged != 1 {
		t.Fatalf("purged %d", stats.RecordsPurged)
	}
	var left, revisions int
	_ = env.Migrator.QueryRow(ctx, `SELECT count(*) FROM records WHERE id = $1`, old.ID).Scan(&left)
	_ = env.Migrator.QueryRow(ctx, `SELECT count(*) FROM record_revisions WHERE record_id = $1`, old.ID).Scan(&revisions)
	if left != 0 || revisions != 0 {
		t.Fatalf("expired record left %d rows and %d revisions", left, revisions)
	}
	// Within retention, undo still works.
	if _, err := env.C.Records.Restore(ctx, eng, "notes", recent.ID, 1, 2); err != nil {
		t.Fatalf("restore within retention: %v", err)
	}
}
