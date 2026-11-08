package main

import (
	"archive/zip"
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// A work-computer transfer uses these exact archives, including the backend.
// Catch stale artifacts and drift between the released query and the storage binding.
func TestCheckedInDreamcatcherUploadsMatchSources(t *testing.T) {
	root := filepath.Join("..")
	dir := t.TempDir()
	if err := pack(root, dir, true); err != nil {
		t.Fatal(err)
	}
	for _, app := range []string{"readiness-notes", "supplier-evidence"} {
		b, err := os.ReadFile(filepath.Join(dir, app+".zip"))
		if err != nil {
			t.Fatal(err)
		}
		shipped, err := os.ReadFile(filepath.Join(root, "uploads", app+".zip"))
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(b, shipped) {
			t.Fatalf("regenerate %s.zip", app)
		}
		reader, err := zip.NewReader(bytes.NewReader(b), int64(len(b)))
		if err != nil {
			t.Fatal(err)
		}
		for _, path := range []string{"Dockerfile", "server.mjs", "dist/index.html", "dist/app.js", "dist/style.css", "src/app.js"} {
			if _, err := reader.Open(path); err != nil {
				t.Fatal(err)
			}
		}
		var profile struct{ Query string }
		var manifest struct{ Queries []string }
		for path, out := range map[string]any{"dist/view.json": &profile, "dreamcatcher.json": &manifest} {
			raw, err := os.ReadFile(filepath.Join(dir, app, path))
			if err != nil {
				t.Fatal(err)
			}
			if err := json.Unmarshal(raw, out); err != nil {
				t.Fatal(err)
			}
		}
		if len(manifest.Queries) != 1 || manifest.Queries[0] != profile.Query {
			t.Fatalf("governed query differs in %s", app)
		}
	}
}
