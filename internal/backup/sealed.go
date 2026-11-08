package backup

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/paulmalmquist/storage_relspace/internal/crypto"
	"github.com/paulmalmquist/storage_relspace/internal/store"
)

// ExportEncryption wraps one fresh export key. Each table has its own sealed stream key;
// the export key authenticates the complete typed manifest, including all file digests.
type ExportEncryption struct {
	ID         string `json:"export_id"`
	KEKID      string `json:"kek_id"`
	WrappedKey []byte `json:"wrapped_key"`
	Auth       []byte `json:"auth"`
}

var exportIDPattern = regexp.MustCompile(`^ex_[0-9a-f]{32}$`)

func tableFile(version int, name string) string {
	path := "tables/" + name + ".ndjson"
	if version == 2 {
		path += ".sbx"
	}
	return path
}
func exportAAD(m *Manifest, purpose string) []byte {
	raw, _ := json.Marshal([]string{"strongbox/export/v2", m.App, m.Encryption.ID, purpose})
	return raw
}

// Canonicalize the actual signed document, not a projection onto today's Go struct.
// Adding optional fields to a future reader must not invalidate already-written bundles.
func manifestAAD(m *Manifest) ([]byte, error) {
	raw := m.rawManifest
	if raw == nil {
		var err error
		raw, err = json.Marshal(m)
		if err != nil {
			return nil, err
		}
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	value, err := uniqueValue(d, 0)
	if err != nil {
		return nil, err
	}
	if _, err := d.Token(); err != io.EOF {
		return nil, errors.New("trailing manifest data")
	}
	object, ok := value.(map[string]any)
	if !ok {
		return nil, errors.New("manifest must be an object")
	}
	encryption, ok := object["encryption"].(map[string]any)
	if !ok {
		return nil, errors.New("manifest has no encryption object")
	}
	encryption["auth"] = nil
	canonical, err := json.Marshal(object)
	if err != nil {
		return nil, err
	}
	aad := exportAAD(m, "manifest")
	return append(append(aad, '\n'), canonical...), nil
}
func uniqueValue(d *json.Decoder, depth int) (any, error) {
	if depth > 64 {
		return nil, errors.New("manifest nesting exceeds 64 levels")
	}
	token, err := d.Token()
	if err != nil {
		return nil, err
	}
	delim, ok := token.(json.Delim)
	if !ok {
		return token, nil
	}
	switch delim {
	case '{':
		object := map[string]any{}
		for d.More() {
			token, err := d.Token()
			if err != nil {
				return nil, err
			}
			key, ok := token.(string)
			if !ok {
				return nil, errors.New("invalid object key")
			}
			if _, exists := object[key]; exists {
				return nil, errors.New("duplicate manifest field")
			}
			value, err := uniqueValue(d, depth+1)
			if err != nil {
				return nil, err
			}
			object[key] = value
		}
		if _, err := d.Token(); err != nil {
			return nil, err
		}
		return object, nil
	case '[':
		out := []any{}
		for d.More() {
			v, err := uniqueValue(d, depth+1)
			if err != nil {
				return nil, err
			}
			out = append(out, v)
		}
		if _, err := d.Token(); err != nil {
			return nil, err
		}
		return out, nil
	}
	return nil, errors.New("invalid manifest JSON")
}

func unlock(ctx context.Context, m *Manifest, kp crypto.KeyProvider) ([]byte, error) {
	key, err := kp.Unwrap(ctx, crypto.WrappedKey{KEKID: m.Encryption.KEKID, Ciphertext: m.Encryption.WrappedKey}, exportAAD(m, "key"))
	if err != nil {
		return nil, fmt.Errorf("unwrapping export key: %w", err)
	}
	if len(key) != crypto.KeyBytes {
		clear(key)
		return nil, errors.New("invalid export key length")
	}
	aad, err := manifestAAD(m)
	if err == nil {
		var plain []byte
		plain, err = crypto.Open(key, m.Encryption.Auth, aad)
		if len(plain) != 0 {
			err = errors.New("invalid manifest authentication payload")
		}
	}
	if err != nil {
		clear(key)
		return nil, fmt.Errorf("manifest authentication failed: %w", err)
	}
	return key, nil
}
func tableReader(dir string, m *Manifest, key []byte) readTable {
	entries := map[string]TableEntry{}
	for _, t := range m.Tables {
		entries[t.Name] = t
	}
	return func(name string, fn func([]byte) error) error {
		entry, ok := entries[name]
		if !ok || entry.File != tableFile(m.FormatVersion, name) {
			return errors.New("missing or noncanonical table")
		}
		f, err := os.Open(filepath.Join(dir, entry.File))
		if err != nil {
			return err
		}
		defer f.Close()
		if m.FormatVersion == 1 {
			return scanLines(f, fn)
		}
		tableKey, err := crypto.Open(key, entry.SealedKey, exportAAD(m, "file-key/"+entry.File))
		if err != nil {
			return err
		}
		defer clear(tableKey)
		if len(tableKey) != crypto.KeyBytes {
			return errors.New("invalid table key length")
		}
		reader, err := crypto.NewDecryptingReader(f, tableKey, exportAAD(m, entry.File))
		if err != nil {
			return err
		}
		return scanLines(reader, fn)
	}
}

// Inspect reads only the bounded manifest. It does not validate/authenticate bundle files.
func Inspect(dir string) (*Manifest, error) { return readManifest(dir) }

// ValidateAuthenticated also checks encrypted rows, scope and reference completeness without
// needing a database. A local provider works fully offline; a KMS provider needs its KMS service.
func ValidateAuthenticated(ctx context.Context, dir string, kp crypto.KeyProvider) (*Manifest, *Report, error) {
	m, rep, err := Validate(dir)
	if err != nil || !rep.OK() {
		return m, rep, err
	}
	if m.FormatVersion != 2 {
		return m, rep, errors.New("legacy exports cannot be authenticated")
	}
	if kp == nil {
		return m, rep, errors.New("a key provider is required")
	}
	key, err := unlock(ctx, m, kp)
	if err != nil {
		return m, nil, err
	}
	defer clear(key)
	rep, err = validateContent(dir, m, tableReader(dir, m, key))
	return m, rep, err
}

// Without a key, a caller can validate stored bytes and canonical inventory, but cannot establish
// authenticity or inspect encrypted row semantics. Report.Level makes that distinction explicit.
func validateTransport(dir string, m *Manifest) (*Manifest, *Report, error) {
	rep := &Report{App: m.App, Level: "transport"}
	if !store.ValidApp(m.App) {
		rep.addf("invalid app identity")
	}
	known := map[string]bool{}
	for _, t := range formatTables(m.FormatVersion) {
		known[t.name] = true
	}
	seen := map[string]bool{}
	for _, t := range m.Tables {
		if !known[t.Name] || seen[t.Name] || t.File != tableFile(2, t.Name) {
			rep.addf("unknown/duplicate table or noncanonical path")
			continue
		}
		seen[t.Name] = true
		if t.Rows < 0 || t.Bytes < crypto.HeaderBytes+crypto.ChunkOverhead || len(t.SealedKey) == 0 {
			rep.addf("invalid encrypted table metadata: %s", t.Name)
		}
		sum, _, size, err := digestFile(filepath.Join(dir, t.File))
		if err != nil || size != t.Bytes || sum != t.SHA256 {
			rep.addf("table %s: size or digest mismatch", t.Name)
		}
		rep.Tables++
		rep.Rows += t.Rows
	}
	for _, t := range formatTables(m.FormatVersion) {
		if !seen[t.name] {
			rep.addf("missing table %s", t.name)
		}
	}
	if m.Objects.File != "objects.ndjson" {
		rep.addf("noncanonical object inventory")
		return m, rep, nil
	}
	sum, _, _, err := digestFile(filepath.Join(dir, m.Objects.File))
	if err != nil || sum != m.Objects.SHA256 {
		rep.addf("object inventory digest mismatch")
		return m, rep, nil
	}
	objects := map[string]bool{}
	err = eachLine(filepath.Join(dir, m.Objects.File), func(raw []byte) error {
		if _, err := decodeRow(raw); err != nil {
			return err
		}
		var o ObjectEntry
		if err := json.Unmarshal(raw, &o); err != nil {
			return err
		}
		if !store.ValidStorageKey(o.Key) || strings.HasPrefix(o.Key, "apps/") && !strings.HasPrefix(o.Key, "apps/"+strings.ReplaceAll(m.App, ":", "/")+"/") {
			rep.addf("object outside app scope")
			return nil
		}
		if objects[o.Key] {
			rep.addf("duplicate object")
			return nil
		}
		objects[o.Key] = true
		path, err := objectPath(dir, o.Key)
		if err != nil {
			return err
		}
		sum, _, size, err := digestFile(path)
		if err != nil || size != o.Bytes || sum != o.SHA256 {
			rep.addf("object %s: size or digest mismatch", o.Key)
		}
		if digest, err := hex.DecodeString(o.SHA256); err != nil || len(digest) != 32 {
			rep.addf("invalid object digest")
		}
		rep.Objects++
		rep.Bytes += size
		return nil
	})
	if rep.Objects != m.Objects.Count || rep.Bytes != m.Objects.Bytes {
		rep.addf("object inventory count/bytes mismatch")
	}
	return m, rep, err
}
