// Pack the two allowlisted sample applications and optionally materialize their
// exact ZIP entries for the local runtime. No third-party package is executed.
package main

import (
	"archive/zip"
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
)

func main() {
	root := flag.String("root", "examples/dreamcatcher", "example directory")
	out := flag.String("out", "dist/dreamcatcher", "output directory")
	stage := flag.Bool("stage", false, "also extract these newly built ZIPs under the output directory")
	flag.Parse()
	if err := pack(*root, *out, *stage); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func pack(root, out string, stage bool) error {
	raw, err := os.ReadFile(filepath.Join(root, "profiles.json"))
	if err != nil {
		return err
	}
	var profiles map[string]json.RawMessage
	if err = json.Unmarshal(raw, &profiles); err != nil {
		return err
	}
	if err = os.MkdirAll(out, 0755); err != nil {
		return err
	}
	for _, slug := range []string{"readiness-notes", "supplier-evidence"} {
		files := map[string][]byte{"dist/view.json": profiles[slug]}
		for _, name := range []string{"Dockerfile", "server.mjs", "dist/index.html", "dist/style.css", "dist/app.js", "dreamcatcher.json"} {
			dir := filepath.Join(root, "runtime")
			if name == "dreamcatcher.json" {
				dir = filepath.Join(root, "apps", slug)
			}
			files[name], err = os.ReadFile(filepath.Join(dir, name))
			if err != nil {
				return err
			}
		}
		files["src/app.js"] = files["dist/app.js"]
		names := make([]string, 0, len(files))
		for name := range files {
			names = append(names, name)
		}
		sort.Strings(names)
		var buf bytes.Buffer
		z := zip.NewWriter(&buf)
		for _, name := range names {
			entry, err := z.Create(name)
			if err != nil {
				return err
			}
			if _, err = entry.Write(files[name]); err != nil {
				return err
			}
		}
		if err = z.Close(); err != nil {
			return err
		}
		if err = os.WriteFile(filepath.Join(out, slug+".zip"), buf.Bytes(), 0644); err != nil {
			return err
		}
		if stage {
			reader, err := zip.NewReader(bytes.NewReader(buf.Bytes()), int64(buf.Len()))
			if err != nil {
				return err
			}
			for _, f := range reader.File {
				r, err := f.Open()
				if err != nil {
					return err
				}
				data, err := io.ReadAll(r)
				r.Close()
				if err != nil {
					return err
				}
				path := filepath.Join(out, slug, f.Name)
				if err = os.MkdirAll(filepath.Dir(path), 0755); err != nil {
					return err
				}
				if err = os.WriteFile(path, data, 0644); err != nil {
					return err
				}
			}
		}
		fmt.Printf("%x  %s.zip\n", sha256.Sum256(buf.Bytes()), slug)
	}
	return nil
}
