package crypto

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"hash/crc32"
	"log/slog"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"cloud.google.com/go/kms/apiv1/kmspb"
	"github.com/googleapis/gax-go/v2"
	"google.golang.org/protobuf/types/known/wrapperspb"

	"github.com/paulmalmquist/storage_relspace/internal/errs"
)

// WrappedKey is a data key encrypted under a key-encryption key (KEK).
type WrappedKey struct {
	KEKID      string
	Ciphertext []byte
}

// KeyProvider wraps and unwraps data keys. Both operations are bound to caller-supplied AAD, so a
// wrapped key lifted from one object cannot be unwrapped in the context of another.
type KeyProvider interface {
	Wrap(ctx context.Context, plaintextKey, aad []byte) (WrappedKey, error)
	Unwrap(ctx context.Context, w WrappedKey, aad []byte) ([]byte, error)
	Describe() map[string]any
}

// ---------------------------------------------------------------------------------------------
// Local keyring (development and tests only; production mode refuses it)
// ---------------------------------------------------------------------------------------------

const localPrefix = "local:"

type keyringFile struct {
	Active string            `json:"active"`
	Keys   map[string]string `json:"keys"`
}

type LocalKeyProvider struct {
	keys   map[string][]byte
	active string
}

func LoadLocalKeyring(path string) (*LocalKeyProvider, error) {
	raw, err := os.ReadFile(path) //nolint:gosec // operator-supplied path
	if err != nil {
		return nil, errs.Config("local keyring not found at %s; run `strongbox keyring create`", path).Wrap(err)
	}
	if st, err := os.Stat(path); err == nil && st.Mode().Perm()&0o077 != 0 {
		slog.Warn("local keyring is readable by group/other; chmod 600 it", "path", path)
	}
	var f keyringFile
	if err := json.Unmarshal(raw, &f); err != nil {
		return nil, errs.Config("local keyring is malformed").Wrap(err)
	}
	p := &LocalKeyProvider{keys: map[string][]byte{}, active: f.Active}
	for id, b64 := range f.Keys {
		k, err := base64.StdEncoding.DecodeString(b64)
		if err != nil || len(k) != KeyBytes {
			return nil, errs.Config("local keyring key %s is malformed", id)
		}
		p.keys[id] = k
	}
	if _, ok := p.keys[p.active]; !ok {
		return nil, errs.Config("local keyring has no active key")
	}
	return p, nil
}

func writeKeyring(path string, f keyringFile) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	raw, err := json.Marshal(f)
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, raw, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// CreateLocalKeyring writes a new keyring with one active key.
func CreateLocalKeyring(path string) (string, error) {
	if _, err := os.Stat(path); err == nil {
		return "", errs.Config("keyring already exists at %s", path)
	}
	f := keyringFile{Active: "k1", Keys: map[string]string{"k1": base64.StdEncoding.EncodeToString(NewDataKey())}}
	return "k1", writeKeyring(path, f)
}

// RotateLocalKeyring adds a key and makes it active; old keys stay for unwrapping.
func RotateLocalKeyring(path string) (string, error) {
	raw, err := os.ReadFile(path) //nolint:gosec // operator-supplied path
	if err != nil {
		return "", err
	}
	var f keyringFile
	if err := json.Unmarshal(raw, &f); err != nil {
		return "", err
	}
	id := fmt.Sprintf("k%d", len(f.Keys)+1)
	f.Keys[id] = base64.StdEncoding.EncodeToString(NewDataKey())
	f.Active = id
	return id, writeKeyring(path, f)
}

func (p *LocalKeyProvider) Wrap(_ context.Context, key, aad []byte) (WrappedKey, error) {
	ct, err := Seal(p.keys[p.active], key, aad)
	return WrappedKey{KEKID: localPrefix + p.active, Ciphertext: ct}, err
}

func (p *LocalKeyProvider) Unwrap(_ context.Context, w WrappedKey, aad []byte) ([]byte, error) {
	if !strings.HasPrefix(w.KEKID, localPrefix) {
		return nil, errs.Integrity("key was wrapped by a different provider (%s)", w.KEKID)
	}
	kek, ok := p.keys[strings.TrimPrefix(w.KEKID, localPrefix)]
	if !ok {
		return nil, errs.Integrity("unknown key-encryption key %s", w.KEKID)
	}
	return Open(kek, w.Ciphertext, aad)
}

func (p *LocalKeyProvider) Describe() map[string]any {
	return map[string]any{"provider": "local", "active_kek": localPrefix + p.active, "production_safe": false}
}

// ---------------------------------------------------------------------------------------------
// Google Cloud KMS. Use an HSM-protection-level key (FIPS 140 Level 3) in production. Requests carry
// AAD and are checked end to end with CRC32C, as Google recommends.
// ---------------------------------------------------------------------------------------------

const gcpPrefix = "gcpkms:"

var keyNameRe = regexp.MustCompile(`^projects/[^/]+/locations/[^/]+/keyRings/[^/]+/cryptoKeys/[^/]+$`)
var castagnoli = crc32.MakeTable(crc32.Castagnoli)

// KMSClient is the subset of *kms.KeyManagementClient used here.
type KMSClient interface {
	Encrypt(ctx context.Context, req *kmspb.EncryptRequest, opts ...gax.CallOption) (*kmspb.EncryptResponse, error)
	Decrypt(ctx context.Context, req *kmspb.DecryptRequest, opts ...gax.CallOption) (*kmspb.DecryptResponse, error)
}

type GCPKeyProvider struct {
	keyName string
	client  KMSClient
}

func NewGCPKeyProvider(keyName string, client KMSClient) (*GCPKeyProvider, error) {
	if !keyNameRe.MatchString(keyName) {
		return nil, errs.Config("kms_key_name must be projects/*/locations/*/keyRings/*/cryptoKeys/*")
	}
	return &GCPKeyProvider{keyName: keyName, client: client}, nil
}

func crc(b []byte) int64 { return int64(crc32.Checksum(b, castagnoli)) }

func (g *GCPKeyProvider) Wrap(ctx context.Context, key, aad []byte) (WrappedKey, error) {
	resp, err := g.client.Encrypt(ctx, &kmspb.EncryptRequest{
		Name:                              g.keyName,
		Plaintext:                         key,
		PlaintextCrc32C:                   wrapperspb.Int64(crc(key)),
		AdditionalAuthenticatedData:       aad,
		AdditionalAuthenticatedDataCrc32C: wrapperspb.Int64(crc(aad)),
	})
	if err != nil {
		return WrappedKey{}, fmt.Errorf("cloud kms encrypt: %w", err)
	}
	if !resp.GetVerifiedPlaintextCrc32C() || !resp.GetVerifiedAdditionalAuthenticatedDataCrc32C() {
		return WrappedKey{}, errs.Integrity("Cloud KMS did not verify request integrity")
	}
	if crc(resp.GetCiphertext()) != resp.GetCiphertextCrc32C().GetValue() {
		return WrappedKey{}, errs.Integrity("Cloud KMS response corrupted in transit")
	}
	if !strings.HasPrefix(resp.GetName(), g.keyName+"/cryptoKeyVersions/") {
		return WrappedKey{}, errs.Integrity("Cloud KMS used an unexpected key")
	}
	return WrappedKey{KEKID: gcpPrefix + resp.GetName(), Ciphertext: resp.GetCiphertext()}, nil
}

func (g *GCPKeyProvider) Unwrap(ctx context.Context, w WrappedKey, aad []byte) ([]byte, error) {
	if !strings.HasPrefix(w.KEKID, gcpPrefix) {
		return nil, errs.Integrity("key was wrapped by a different provider (%s)", w.KEKID)
	}
	version := strings.TrimPrefix(w.KEKID, gcpPrefix)
	keyName, _, _ := strings.Cut(version, "/cryptoKeyVersions/")
	if keyName != g.keyName {
		return nil, errs.Integrity("wrapped key belongs to a key outside this deployment")
	}
	resp, err := g.client.Decrypt(ctx, &kmspb.DecryptRequest{
		Name:                              keyName,
		Ciphertext:                        w.Ciphertext,
		CiphertextCrc32C:                  wrapperspb.Int64(crc(w.Ciphertext)),
		AdditionalAuthenticatedData:       aad,
		AdditionalAuthenticatedDataCrc32C: wrapperspb.Int64(crc(aad)),
	})
	if err != nil {
		return nil, fmt.Errorf("cloud kms decrypt: %w", err)
	}
	if crc(resp.GetPlaintext()) != resp.GetPlaintextCrc32C().GetValue() {
		return nil, errs.Integrity("Cloud KMS response corrupted in transit")
	}
	if len(resp.GetPlaintext()) != KeyBytes {
		return nil, errs.Integrity("unwrapped key has the wrong length")
	}
	return resp.GetPlaintext(), nil
}

func (g *GCPKeyProvider) Describe() map[string]any {
	return map[string]any{"provider": "gcp-kms", "key": g.keyName, "production_safe": true}
}
