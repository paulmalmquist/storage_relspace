package crypto

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"cloud.google.com/go/kms/apiv1/kmspb"
	"github.com/googleapis/gax-go/v2"
	"google.golang.org/protobuf/types/known/wrapperspb"

	"github.com/paulmalmquist/storage_relspace/internal/errs"
)

const chunk = 4096

func randBytes(n int) []byte {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return b
}

func encrypt(t *testing.T, key, pt, ctx []byte) []byte {
	t.Helper()
	enc, err := NewStreamEncryptor(key, ctx, chunk)
	if err != nil {
		t.Fatal(err)
	}
	out := enc.Header()
	for i := 0; i < len(pt); i += 1000 {
		seg, err := enc.Update(pt[i:min(i+1000, len(pt))])
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, seg...)
	}
	tail, err := enc.Finalize()
	if err != nil {
		t.Fatal(err)
	}
	return append(out, tail...)
}

func decrypt(key, ct, ctx []byte) ([]byte, error) {
	r, err := NewDecryptingReader(io.MultiReader(bytes.NewReader(ct)), key, ctx)
	if err != nil {
		return nil, err
	}
	return io.ReadAll(r)
}

func TestStreamRoundTrip(t *testing.T) {
	for _, size := range []int{0, 1, chunk - 1, chunk, chunk + 1, 3 * chunk, 50_000} {
		key, pt := NewDataKey(), randBytes(size)
		ct := encrypt(t, key, pt, []byte("ctx"))
		segments := max(1, (size+chunk-1)/chunk)
		if len(ct) != HeaderBytes+size+segments*ChunkOverhead {
			t.Errorf("size %d: unexpected ciphertext length %d", size, len(ct))
		}
		got, err := decrypt(key, ct, []byte("ctx"))
		if err != nil || !bytes.Equal(got, pt) {
			t.Errorf("size %d: round trip failed: %v", size, err)
		}
	}
}

func TestCiphertextHidesPlaintext(t *testing.T) {
	pt := bytes.Repeat([]byte("TERRAN-R-INJECTOR-GEOMETRY "), 500)
	if bytes.Contains(encrypt(t, NewDataKey(), pt, []byte("c")), []byte("INJECTOR")) {
		t.Fatal("plaintext visible in ciphertext")
	}
}

func expectIntegrity(t *testing.T, err error) {
	t.Helper()
	if !errs.Is(err, "integrity_violation") {
		t.Fatalf("want integrity violation, got %v", err)
	}
}

func TestTamperingDetected(t *testing.T) {
	key := NewDataKey()
	seg := chunk + ChunkOverhead

	ct := encrypt(t, key, randBytes(10_000), []byte("ctx"))
	flipped := append([]byte(nil), ct...)
	flipped[HeaderBytes+5000] ^= 1
	_, err := decrypt(key, flipped, []byte("ctx"))
	expectIntegrity(t, err)

	ct = encrypt(t, key, randBytes(3*chunk+10), []byte("ctx"))
	_, err = decrypt(key, ct[:HeaderBytes+2*seg], []byte("ctx")) // drop the final segment
	expectIntegrity(t, err)

	body := ct[HeaderBytes:]
	swapped := append(append(append(append([]byte(nil), ct[:HeaderBytes]...), body[seg:2*seg]...), body[:seg]...), body[2*seg:]...)
	_, err = decrypt(key, swapped, []byte("ctx"))
	expectIntegrity(t, err)

	ct = encrypt(t, key, randBytes(2*chunk), []byte("ctx"))
	_, err = decrypt(key, append(append([]byte(nil), ct...), ct[HeaderBytes:HeaderBytes+seg]...), []byte("ctx"))
	expectIntegrity(t, err)

	ct = encrypt(t, key, []byte("data"), []byte("strongbox/blob/v2|blb_a|CUI//SP-EXPT"))
	_, err = decrypt(key, ct, []byte("strongbox/blob/v2|blb_a|UNCONTROLLED"))
	expectIntegrity(t, err)
}

func TestHeaderBounds(t *testing.T) {
	h := header(chunk)
	binary.BigEndian.PutUint32(h[6:], 1<<30)
	if _, err := parseHeader(h); err == nil {
		t.Fatal("oversized chunk accepted")
	}
}

func TestSeal(t *testing.T) {
	key := NewDataKey()
	sealed, err := Seal(key, []byte("secret"), []byte("aad-1"))
	if err != nil {
		t.Fatal(err)
	}
	if pt, err := Open(key, sealed, []byte("aad-1")); err != nil || string(pt) != "secret" {
		t.Fatalf("open failed: %v", err)
	}
	_, err = Open(key, sealed, []byte("aad-2"))
	expectIntegrity(t, err)
	_, err = Open(NewDataKey(), sealed, []byte("aad-1"))
	expectIntegrity(t, err)
}

func TestLocalKeyringRotation(t *testing.T) {
	path := filepath.Join(t.TempDir(), "kr.json")
	if _, err := CreateLocalKeyring(path); err != nil {
		t.Fatal(err)
	}
	if st, _ := os.Stat(path); st.Mode().Perm() != 0o600 {
		t.Errorf("keyring mode %v", st.Mode().Perm())
	}
	ctx, dek := context.Background(), NewDataKey()
	p1, _ := LoadLocalKeyring(path)
	w1, _ := p1.Wrap(ctx, dek, []byte("ctx"))
	if _, err := RotateLocalKeyring(path); err != nil {
		t.Fatal(err)
	}
	p2, _ := LoadLocalKeyring(path)
	w2, _ := p2.Wrap(ctx, dek, []byte("ctx"))
	if w1.KEKID != "local:k1" || w2.KEKID != "local:k2" {
		t.Errorf("kek ids %s %s", w1.KEKID, w2.KEKID)
	}
	if got, err := p2.Unwrap(ctx, w1, []byte("ctx")); err != nil || !bytes.Equal(got, dek) {
		t.Fatal("old KEK must still unwrap")
	}
	_, err := p2.Unwrap(ctx, w1, []byte("other"))
	expectIntegrity(t, err)
}

// fakeKMS stands in for *kms.KeyManagementClient.
type fakeKMS struct {
	key     string
	kek     []byte
	corrupt bool
}

func (f *fakeKMS) Encrypt(_ context.Context, r *kmspb.EncryptRequest, _ ...gax.CallOption) (*kmspb.EncryptResponse, error) {
	if r.Name != f.key || crc(r.Plaintext) != r.PlaintextCrc32C.GetValue() {
		panic("bad request")
	}
	ct, _ := Seal(f.kek, r.Plaintext, r.AdditionalAuthenticatedData)
	c := crc(ct)
	if f.corrupt {
		c++
	}
	return &kmspb.EncryptResponse{
		Name: f.key + "/cryptoKeyVersions/3", Ciphertext: ct, CiphertextCrc32C: wrapperspb.Int64(c),
		VerifiedPlaintextCrc32C: true, VerifiedAdditionalAuthenticatedDataCrc32C: true,
	}, nil
}

func (f *fakeKMS) Decrypt(_ context.Context, r *kmspb.DecryptRequest, _ ...gax.CallOption) (*kmspb.DecryptResponse, error) {
	pt, err := Open(f.kek, r.Ciphertext, r.AdditionalAuthenticatedData)
	if err != nil {
		return nil, err
	}
	return &kmspb.DecryptResponse{Plaintext: pt, PlaintextCrc32C: wrapperspb.Int64(crc(pt))}, nil
}

const keyName = "projects/p/locations/us-east4/keyRings/strongbox/cryptoKeys/data"

func TestGCPKMS(t *testing.T) {
	ctx := context.Background()
	p, err := NewGCPKeyProvider(keyName, &fakeKMS{key: keyName, kek: NewDataKey()})
	if err != nil {
		t.Fatal(err)
	}
	dek := NewDataKey()
	w, err := p.Wrap(ctx, dek, []byte("ctx"))
	if err != nil || w.KEKID != "gcpkms:"+keyName+"/cryptoKeyVersions/3" {
		t.Fatalf("wrap: %v %s", err, w.KEKID)
	}
	if got, err := p.Unwrap(ctx, w, []byte("ctx")); err != nil || !bytes.Equal(got, dek) {
		t.Fatalf("unwrap: %v", err)
	}

	bad, _ := NewGCPKeyProvider(keyName, &fakeKMS{key: keyName, kek: NewDataKey(), corrupt: true})
	_, err = bad.Wrap(ctx, dek, []byte("ctx"))
	expectIntegrity(t, err)

	_, err = p.Unwrap(ctx, WrappedKey{KEKID: "gcpkms:projects/evil/locations/x/keyRings/r/cryptoKeys/k/cryptoKeyVersions/1"}, nil)
	expectIntegrity(t, err)
	_, err = p.Unwrap(ctx, WrappedKey{KEKID: "local:k1"}, nil)
	expectIntegrity(t, err)

	if _, err := NewGCPKeyProvider("not-a-key", nil); err == nil {
		t.Fatal("invalid key name accepted")
	}
}

func TestFIPSStatus(t *testing.T) {
	s := FIPSStatus()
	if _, ok := s["fips_enabled"].(bool); !ok || !strings.HasPrefix(s["go_version"].(string), "go") {
		t.Fatalf("unexpected status %v", s)
	}
}
