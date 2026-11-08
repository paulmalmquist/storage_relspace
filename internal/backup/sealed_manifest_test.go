package backup

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/paulmalmquist/storage_relspace/internal/crypto"
)

func TestManifestAuthPreservesUnknownSignedFieldsAndRejectsDuplicates(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "keyring.json")
	if _, err := crypto.CreateLocalKeyring(path); err != nil {
		t.Fatal(err)
	}
	kp, err := crypto.LoadLocalKeyring(path)
	if err != nil {
		t.Fatal(err)
	}
	key := crypto.NewDataKey()
	m := &Manifest{Format: Format, FormatVersion: 2, App: "acme:test", Encryption: &ExportEncryption{ID: "ex_01234567890123456789012345678901"}}
	wrapped, err := kp.Wrap(context.Background(), key, exportAAD(m, "key"))
	if err != nil {
		t.Fatal(err)
	}
	m.Encryption.KEKID, m.Encryption.WrappedKey = wrapped.KEKID, wrapped.Ciphertext
	raw, _ := json.Marshal(m)
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	var doc map[string]any
	if err := decoder.Decode(&doc); err != nil {
		t.Fatal(err)
	}
	doc["future_optional_metadata"] = map[string]any{"large_integer": json.Number("9007199254740993")}
	// Independent format definition: lexicographically sorted map keys, exact JSON numbers,
	// and encryption.auth set to null, prefixed by the manifest context and newline.
	canonical, _ := json.Marshal(doc)
	aad := append(exportAAD(m, "manifest"), '\n')
	aad = append(aad, canonical...)
	auth, err := crypto.Seal(key, nil, aad)
	if err != nil {
		t.Fatal(err)
	}
	doc["encryption"].(map[string]any)["auth"] = auth
	raw, _ = json.MarshalIndent(doc, "", "  ")
	manifestPath := filepath.Join(dir, "manifest.json")
	if err := os.WriteFile(manifestPath, raw, 0600); err != nil {
		t.Fatal(err)
	}
	parsed, err := readManifest(dir)
	if err != nil {
		t.Fatal(err)
	}
	opened, err := unlock(context.Background(), parsed, kp)
	if err != nil || !bytes.Equal(opened, key) {
		t.Fatalf("reader dropped signed fields or rounded integers: %v", err)
	}
	// A duplicate nested field with the same final value must still be rejected.
	duplicated := bytes.Replace(raw, []byte(`"kek_id": "local:k1"`), []byte(`"kek_id":"wrong", "kek_id": "local:k1"`), 1)
	if bytes.Equal(duplicated, raw) {
		t.Fatal("duplicate fixture did not change")
	}
	if err := os.WriteFile(manifestPath, duplicated, 0600); err != nil {
		t.Fatal(err)
	}
	parsed, err = readManifest(dir)
	if err == nil {
		_, err = unlock(context.Background(), parsed, kp)
	}
	if err == nil {
		t.Fatal("duplicate manifest field accepted")
	}
}
