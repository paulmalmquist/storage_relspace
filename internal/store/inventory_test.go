package store

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"cloud.google.com/go/storage"
	"google.golang.org/api/option"
)

func TestLocalConcurrentWritersNeverReplaceCommittedObject(t *testing.T) {
	l, err := NewLocal(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if _, err := l.OpenWriter(ctx, "x"); err == nil {
		t.Fatal("one-character legacy key accepted")
	}
	key := "apps/acme/test/blob/cipher"
	first, err := l.OpenWriter(ctx, key)
	if err != nil {
		t.Fatal(err)
	}
	second, err := l.OpenWriter(ctx, key)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = first.Write([]byte("first"))
	_, _ = second.Write([]byte("second"))
	if err := first.Commit(); err != nil {
		t.Fatal(err)
	}
	if err := second.Commit(); err == nil {
		t.Fatal("second writer replaced an existing generation")
	}
	r, err := l.Read(ctx, key)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	raw, err := io.ReadAll(r)
	if err != nil || string(raw) != "first" {
		t.Fatalf("committed bytes changed: %q %v", raw, err)
	}
}
func TestLocalInventoryPaginationAndConditionalDelete(t *testing.T) {
	root := t.TempDir()
	l, err := NewLocal(root)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	keys := []string{"apps/acme/test/a/z", "apps/acme/test/a.b", "apps/acme/test/a0", "apps/acme/test/a/c"}
	for _, key := range keys {
		w, err := l.OpenWriter(ctx, key)
		if err != nil {
			t.Fatal(err)
		}
		_, _ = w.Write([]byte(key))
		if err := w.Commit(); err != nil {
			t.Fatal(err)
		}
	}
	var got []string
	for after := ""; ; {
		page, next, err := l.ListObjects(ctx, "apps/acme/test/", after, 1)
		if err != nil {
			t.Fatal(err)
		}
		for _, o := range page {
			got = append(got, o.Key)
		}
		if next == "" {
			break
		}
		after = next
	}
	slices.Sort(keys)
	if !slices.Equal(got, keys) {
		t.Fatalf("inventory skipped/reordered keys: %v want %v", got, keys)
	}
	old, err := l.StatObject(ctx, keys[0])
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, keys[0]), []byte("replacement"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := l.DeleteVersion(ctx, old); !errors.Is(err, ErrObjectChanged) {
		t.Fatalf("stale delete: %v", err)
	}
	fresh, err := l.StatObject(ctx, keys[0])
	if err != nil {
		t.Fatal(err)
	}
	if err := l.DeleteVersion(ctx, fresh); err != nil {
		t.Fatal(err)
	}
	if _, err := l.StatObject(ctx, keys[0]); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("conditional delete left file: %v", err)
	}
	if _, _, err := l.ListObjects(ctx, "apps/acme/test/", "apps/rival/test/key", 1); err == nil {
		t.Fatal("foreign cursor accepted")
	}
}
func TestGCSInventoryConditionalDeletePinsBothGenerations(t *testing.T) {
	var deleted bool
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "DELETE" {
			if r.URL.Query().Get("ifGenerationMatch") != "17" || r.URL.Query().Get("ifMetagenerationMatch") != "4" {
				t.Errorf("missing generation preconditions: %s", r.URL)
			}
			deleted = true
			w.WriteHeader(412)
			fmt.Fprint(w, `{"error":{"code":412,"message":"changed"}}`)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"name":"apps/acme/test/blob/cipher","size":"5","generation":"17","metageneration":"4","updated":"2026-01-01T00:00:00Z"}`)
	}))
	defer server.Close()
	client, err := storage.NewClient(context.Background(), option.WithEndpoint(server.URL), option.WithoutAuthentication(), option.WithHTTPClient(server.Client()))
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	g := gcsAPI{bucket: client.Bucket("bucket")}
	o, err := g.statObject(context.Background(), "apps/acme/test/blob/cipher")
	if err != nil {
		t.Fatal(err)
	}
	if o.Version != "17:4" {
		t.Fatalf("bad generation %s", o.Version)
	}
	if err := g.deleteVersion(context.Background(), o); !errors.Is(err, ErrObjectChanged) {
		t.Fatalf("changed generation delete: %v", err)
	}
	if !deleted {
		t.Fatal("no delete request")
	}
}
