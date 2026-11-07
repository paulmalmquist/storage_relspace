package client_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"io"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/paulmalmquist/storage_relspace/internal/api"
	"github.com/paulmalmquist/storage_relspace/internal/testenv"
	"github.com/paulmalmquist/storage_relspace/pkg/client"
)

// These tests replace the former Python client suite: the Go SDK against the real API and Postgres.

func newClient(t *testing.T, subject string) (*client.Client, *testenv.Env) {
	t.Helper()
	env := testenv.New(t)
	srv := httptest.NewServer(api.New(env.C))
	t.Cleanup(srv.Close)
	return client.New(srv.URL, client.StaticToken(testenv.Token(t, subject))), env
}

func TestBlobRoundTripMetadataAndMarking(t *testing.T) {
	sb, env := newClient(t, "svc-mes@rel.test")
	ctx := context.Background()
	data := make([]byte, 300_000)
	_, _ = rand.Read(data)
	meta, err := sb.PutBlob(ctx, data, client.BlobOptions{Marking: "cui//sp-expt", ContentType: "text/csv",
		Filename: "weld map.csv", Metadata: map[string]any{"lot": 7}})
	if err != nil {
		t.Fatal(err)
	}
	if meta["marking"] != "CUI//SP-EXPT" || meta["filename"] != "weld map.csv" {
		t.Fatalf("unexpected metadata: %v", meta)
	}
	if md, _ := meta["metadata"].(map[string]any); md["lot"] == nil || md["lot"].(interface{ String() string }).String() != "7" {
		t.Fatalf("metadata not preserved: %v", meta["metadata"])
	}
	id := meta["id"].(string)

	// The stored object is ciphertext, not the plaintext.
	stored, err := os.ReadFile(env.ObjectPath(id))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(stored, data[:64]) {
		t.Fatal("plaintext found in stored object")
	}

	got, banner, err := sb.ReadBlob(ctx, id, 0)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, data) || banner != "CUI//SP-EXPT" {
		t.Fatalf("round trip mismatch (banner %q)", banner)
	}
	if _, _, err := sb.ReadBlob(ctx, id, 1000); !client.IsCode(err, "payload_too_large") {
		t.Fatalf("expected read limit error, got %v", err)
	}
}

func TestBlobStreamingAndDeletion(t *testing.T) {
	sb, _ := newClient(t, "svc-mes@rel.test")
	ctx := context.Background()
	data := make([]byte, 1_000_003) // spans many 4 KiB segments and is not a multiple of the chunk
	_, _ = rand.Read(data)
	meta, err := sb.PutBlobStream(ctx, bytes.NewReader(data), client.BlobOptions{Marking: "CUI//PROPIN"})
	if err != nil {
		t.Fatal(err)
	}
	id := meta["id"].(string)
	rc, banner, err := sb.OpenBlob(ctx, id)
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
	if err := sb.DeleteBlob(ctx, id, false); err != nil {
		t.Fatal(err)
	}
	if _, err := sb.GetBlob(ctx, id); !client.IsCode(err, "not_found") {
		t.Fatalf("deleted blob still readable: %v", err)
	}
}

func TestRecordsCRUDQueryStaleAndSchema(t *testing.T) {
	sb, _ := newClient(t, "svc-mes@rel.test")
	ctx := context.Background()
	if _, err := sb.CreateCollection(ctx, client.CollectionSpec{Name: "parts", Marking: "CUI//SP-EXPT",
		IndexedFields: []string{"part_number"}, JSONSchema: map[string]any{"type": "object", "required": []string{"part_number"},
			"properties": map[string]any{"part_number": map[string]any{"type": "string"}}}}); err != nil {
		t.Fatal(err)
	}
	rec, err := sb.CreateRecord(ctx, "parts", map[string]any{"part_number": "TR-1", "status": "open"}, "")
	if err != nil {
		t.Fatal(err)
	}
	id := rec["id"].(string)
	upd, err := sb.UpdateRecord(ctx, "parts", id, map[string]any{"part_number": "TR-1", "status": "closed"}, 1, "")
	if err != nil {
		t.Fatal(err)
	}
	if upd["version"].(interface{ String() string }).String() != "2" {
		t.Fatalf("version not advanced: %v", upd["version"])
	}
	if _, err := sb.UpdateRecord(ctx, "parts", id, map[string]any{"part_number": "TR-1"}, 1, ""); !client.IsCode(err, "precondition_failed") {
		t.Fatalf("stale update accepted: %v", err)
	}
	page, err := sb.Query(ctx, "parts", map[string]any{"part_number": "TR-1"}, 0, "")
	if err != nil {
		t.Fatal(err)
	}
	items := page["items"].([]any)
	if len(items) != 1 || items[0].(map[string]any)["data"].(map[string]any)["status"] != "closed" {
		t.Fatalf("query returned %v", items)
	}
	if page["marking"] != "CUI//SP-EXPT" {
		t.Fatalf("query marking %v", page["marking"])
	}
	if _, err := sb.CreateRecord(ctx, "parts", map[string]any{"status": "missing part number"}, ""); !client.IsCode(err, "validation_failed") {
		t.Fatalf("schema violation accepted: %v", err)
	}
	if err := sb.DeleteRecord(ctx, "parts", id, 1, false); !client.IsCode(err, "precondition_failed") {
		t.Fatalf("stale delete accepted: %v", err)
	}
	if err := sb.DeleteRecord(ctx, "parts", id, 2, false); err != nil {
		t.Fatal(err)
	}
	if _, err := sb.GetRecord(ctx, "parts", id); !client.IsCode(err, "not_found") {
		t.Fatalf("deleted record still readable: %v", err)
	}
}
