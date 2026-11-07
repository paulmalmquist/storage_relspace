package client_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"sync/atomic"
	"testing"

	"github.com/paulmalmquist/storage_relspace/internal/api"
	"github.com/paulmalmquist/storage_relspace/internal/testenv"
	"github.com/paulmalmquist/storage_relspace/pkg/client"
)

// The Go SDK against the real API and Postgres (this replaced the former Python client suite).

type harness struct {
	env *testenv.Env
	srv *httptest.Server
}

func newHarness(t *testing.T) *harness {
	t.Helper()
	env := testenv.New(t)
	srv := httptest.NewServer(api.New(env.C))
	t.Cleanup(srv.Close)
	return &harness{env: env, srv: srv}
}

func (h *harness) app(t *testing.T, subject string, opts ...client.Option) *client.App {
	return client.New(h.srv.URL, client.StaticToken(testenv.Token(t, subject)), opts...).App(testenv.AppID)
}

func TestBlobRoundTripMetadataAndMarking(t *testing.T) {
	h := newHarness(t)
	sb := h.app(t, "svc-mes@rel.test")
	ctx := context.Background()
	data := make([]byte, 300_000)
	_, _ = rand.Read(data)
	meta, err := sb.PutBlob(ctx, data, client.BlobOptions{Marking: "cui//sp-expt", ContentType: "text/csv",
		Filename: "weld map.csv", Metadata: map[string]any{"lot": 7}})
	if err != nil {
		t.Fatal(err)
	}
	if meta.Marking != "CUI//SP-EXPT" || *meta.Filename != "weld map.csv" || meta.Metadata["lot"] == nil || meta.Owner != "svc-mes@rel.test" {
		t.Fatalf("unexpected metadata: %+v", meta)
	}
	stored, err := os.ReadFile(h.env.ObjectPath(t, meta.ID))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(stored, data[:64]) {
		t.Fatal("plaintext found in stored object")
	}
	got, banner, err := sb.ReadBlob(ctx, meta.ID, 0)
	if err != nil || !bytes.Equal(got, data) || banner != "CUI//SP-EXPT" {
		t.Fatalf("round trip mismatch (banner %q): %v", banner, err)
	}
	if _, _, err := sb.ReadBlob(ctx, meta.ID, 1000); !client.IsCode(err, "payload_too_large") {
		t.Fatalf("expected read limit error, got %v", err)
	}
}

func TestBlobStreamingAndDeletion(t *testing.T) {
	h := newHarness(t)
	sb := h.app(t, "svc-mes@rel.test")
	ctx := context.Background()
	data := make([]byte, 1_000_003) // many 4 KiB segments, not a multiple of the chunk
	_, _ = rand.Read(data)
	meta, err := sb.PutBlobStream(ctx, bytes.NewReader(data), client.BlobOptions{Marking: "CUI//PROPIN"})
	if err != nil {
		t.Fatal(err)
	}
	rc, banner, err := sb.OpenBlob(ctx, meta.ID)
	if err != nil {
		t.Fatal(err)
	}
	var got bytes.Buffer
	buf := make([]byte, 7919)
	for {
		n, err := rc.Read(buf)
		got.Write(buf[:n])
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
	}
	_ = rc.Close()
	if !bytes.Equal(got.Bytes(), data) || banner != "CUI//PROPIN" {
		t.Fatal("streamed content mismatch")
	}
	if err := sb.DeleteBlob(ctx, meta.ID, false); err != nil {
		t.Fatal(err)
	}
	if _, err := sb.GetBlob(ctx, meta.ID); !client.IsCode(err, "not_found") {
		t.Fatalf("deleted blob still readable: %v", err)
	}
}

func TestRecordsCRUDQueryStaleAndSchema(t *testing.T) {
	h := newHarness(t)
	sb := h.app(t, "svc-mes@rel.test")
	ctx := context.Background()
	if _, err := sb.CreateCollection(ctx, client.CollectionSpec{Name: "parts", Marking: "CUI//SP-EXPT",
		IndexedFields: []string{"part_number"}, JSONSchema: map[string]any{"type": "object", "required": []string{"part_number"},
			"properties": map[string]any{"part_number": map[string]any{"type": "string"}}}}); err != nil {
		t.Fatal(err)
	}
	rec, err := sb.CreateRecord(ctx, "parts", client.RecordInput{Data: map[string]any{"part_number": "TR-1", "status": "open"}})
	if err != nil {
		t.Fatal(err)
	}
	upd, err := sb.UpdateRecord(ctx, "parts", rec.ID, 1, client.RecordInput{Data: map[string]any{"part_number": "TR-1", "status": "closed"}})
	if err != nil || upd.Version != 2 {
		t.Fatalf("update: %v %+v", err, upd)
	}
	if _, err := sb.UpdateRecord(ctx, "parts", rec.ID, 1, client.RecordInput{Data: map[string]any{"part_number": "TR-1"}}); !client.IsConflict(err) {
		t.Fatalf("stale update accepted: %v", err)
	}
	page, err := sb.Query(ctx, "parts", map[string]any{"part_number": "TR-1"}, 0, "")
	if err != nil || len(page.Items) != 1 || page.Items[0].Data["status"] != "closed" || page.Marking != "CUI//SP-EXPT" {
		t.Fatalf("query: %v %+v", err, page)
	}
	if _, err := sb.CreateRecord(ctx, "parts", client.RecordInput{Data: map[string]any{"status": "no part number"}}); !client.IsCode(err, "validation_failed") {
		t.Fatalf("schema violation accepted: %v", err)
	}
	if err := sb.DeleteRecord(ctx, "parts", rec.ID, 1, false); !client.IsConflict(err) {
		t.Fatalf("stale delete accepted: %v", err)
	}
	if err := sb.DeleteRecord(ctx, "parts", rec.ID, 2, false); err != nil {
		t.Fatal(err)
	}
	if _, err := sb.GetRecord(ctx, "parts", rec.ID); !client.IsCode(err, "not_found") {
		t.Fatalf("deleted record still readable: %v", err)
	}
}

func TestConflictRecoveryHistoryAndUndo(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	admin := h.app(t, "admin@rel.test")
	if _, err := admin.CreateCollection(ctx, client.CollectionSpec{Name: "notes", Marking: "UNCONTROLLED"}); err != nil {
		t.Fatal(err)
	}
	me, mate := h.app(t, "engineer@rel.test"), h.app(t, "teammate@rel.test")
	team, err := me.CreateTeam(ctx, "crew")
	if err != nil {
		t.Fatal(err)
	}
	if err := me.SetTeamMember(ctx, team.ID, "teammate@rel.test", "editor"); err != nil {
		t.Fatal(err)
	}
	rec, err := me.CreateRecord(ctx, "notes", client.RecordInput{Data: map[string]any{"n": 0}, Visibility: "team", TeamID: team.ID})
	if err != nil {
		t.Fatal(err)
	}
	// Two writers increment concurrently; Mutate recovers from the conflict.
	done := make(chan error, 2)
	for _, w := range []*client.App{me, mate} {
		go func(w *client.App) {
			_, err := w.Mutate(ctx, "notes", rec.ID, 10, func(d map[string]any) (map[string]any, error) {
				n, _ := d["n"].(interface{ Int64() (int64, error) }).Int64()
				return map[string]any{"n": n + 1}, nil
			})
			done <- err
		}(w)
	}
	for range 2 {
		if err := <-done; err != nil {
			t.Fatal(err)
		}
	}
	cur, _ := me.GetRecord(ctx, "notes", rec.ID)
	if cur.Data["n"].(interface{ String() string }).String() != "2" || cur.Version != 3 {
		t.Fatalf("lost update: %+v", cur)
	}
	hist, err := me.History(ctx, "notes", rec.ID, 0, 0)
	if err != nil || len(hist.Items) != 3 {
		t.Fatalf("history: %v %+v", err, hist)
	}
	undone, err := me.Restore(ctx, "notes", rec.ID, 1, 3)
	if err != nil || undone.Version != 4 || undone.Data["n"].(interface{ String() string }).String() != "0" {
		t.Fatalf("undo: %v %+v", err, undone)
	}
	// Operation status for a known operation ID.
	opCtx := client.WithOperationID(ctx, "my-job-12345")
	if _, err := me.UpdateRecord(opCtx, "notes", rec.ID, 4, client.RecordInput{Data: map[string]any{"n": 9}}); err != nil {
		t.Fatal(err)
	}
	rc, err := me.Operation(ctx, "my-job-12345")
	if err != nil || rc.Status != "succeeded" || rc.ResourceVersion != 5 {
		t.Fatalf("receipt %v %+v", err, rc)
	}
	// Sharing.
	if _, err := mate.GetRecord(ctx, "notes", rec.ID); err != nil {
		t.Fatal(err)
	}
	if err := me.Share(ctx, "notes", rec.ID, "private", ""); err != nil {
		t.Fatal(err)
	}
	if _, err := mate.GetRecord(ctx, "notes", rec.ID); !client.IsCode(err, "not_found") {
		t.Fatalf("unshared record still visible: %v", err)
	}
}

// A lost response: the first attempt succeeds on the server but the client sees a 502. The SDK
// retries with the same operation ID and gets the original result instead of a duplicate or a
// version conflict.
func TestLostResponseIsRecovered(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	h.app(t, "admin@rel.test").CreateCollection(ctx, client.CollectionSpec{Name: "notes", Marking: "UNCONTROLLED"}) //nolint:errcheck
	var dropped atomic.Int32
	flaky := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rr := httptest.NewRecorder()
		api.New(h.env.C).ServeHTTP(rr, r)
		if r.Method != "GET" && dropped.Add(1) == 1 {
			w.WriteHeader(http.StatusBadGateway) // the server committed; the response is lost
			return
		}
		for k, v := range rr.Header() {
			w.Header()[k] = v
		}
		w.WriteHeader(rr.Code)
		_, _ = w.Write(rr.Body.Bytes())
	}))
	defer flaky.Close()
	sb := client.New(flaky.URL, client.StaticToken(testenv.Token(t, "engineer@rel.test"))).App(testenv.AppID)
	rec, err := sb.CreateRecord(ctx, "notes", client.RecordInput{Data: map[string]any{"x": 1}})
	if err != nil || !rec.Replayed {
		t.Fatalf("create through a lost response: %v %+v", err, rec)
	}
	page, _ := sb.Query(ctx, "notes", nil, 0, "")
	if len(page.Items) != 1 {
		t.Fatalf("%d records after a retried create", len(page.Items))
	}
}
