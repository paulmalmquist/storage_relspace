// Package crypto implements authenticated encryption with AES-256-GCM only (FIPS-approved, SP 800-38D),
// using Go's native FIPS 140-3 module.
//
// Two formats:
//
//   - Stream (blobs). The object is cut into fixed-size segments. Each segment is sealed with a
//     module-generated random 96-bit nonce (cipher.NewGCMWithRandomNonce), and its authenticated data
//     binds the header, the caller's context, the segment index and a final-segment flag. Reordering,
//     truncation, extension and cross-object substitution all fail authentication, memory stays
//     O(chunk), and the construction is permitted in GODEBUG=fips140=only mode, which rejects GCM
//     with caller-chosen IVs.
//
//   - Sealed (records, metadata, local key wrapping): version(1) | nonce(12) | ciphertext+tag.
//     Callers bound the number of seals per key with data-key rotation (well under 2^32).
//
// Stream header (10 bytes): magic "SBX2" | version u8 | algorithm u8 | chunk_size u32.
package crypto

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"io"

	"github.com/paulmalmquist/storage_relspace/internal/errs"
)

const (
	KeyBytes      = 32
	TagBytes      = 16
	NonceBytes    = 12
	ChunkOverhead = NonceBytes + TagBytes
	HeaderBytes   = 10
	MinChunk      = 4 * 1024
	MaxChunk      = 4 * 1024 * 1024
	formatVersion = 2
	algStream     = 2
	sealVersion   = 1
	maxChunks     = 1<<32 - 1
)

var magic = []byte("SBX2")

// NewDataKey returns a fresh 256-bit key from the CSPRNG.
func NewDataKey() []byte {
	k := make([]byte, KeyBytes)
	if _, err := rand.Read(k); err != nil {
		panic(err) // crypto/rand never fails on supported platforms
	}
	return k
}

func newAEAD(key []byte) (cipher.AEAD, error) {
	if len(key) != KeyBytes {
		return nil, errs.Config("AES-256 keys must be 32 bytes")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCMWithRandomNonce(block)
}

func header(chunk int) []byte {
	h := make([]byte, HeaderBytes)
	copy(h, magic)
	h[4] = formatVersion
	h[5] = algStream
	binary.BigEndian.PutUint32(h[6:], uint32(chunk))
	return h
}

func parseHeader(h []byte) (int, error) {
	if len(h) != HeaderBytes || !bytes.Equal(h[:4], magic) || h[4] != formatVersion || h[5] != algStream {
		return 0, errs.Integrity("unrecognized ciphertext format")
	}
	chunk := int(binary.BigEndian.Uint32(h[6:]))
	if chunk < MinChunk || chunk > MaxChunk {
		return 0, errs.Integrity("ciphertext chunk size out of bounds")
	}
	return chunk, nil
}

func bind(h, context []byte) []byte {
	out := make([]byte, 0, len(h)+4+len(context)+5)
	out = append(out, h...)
	out = binary.BigEndian.AppendUint32(out, uint32(len(context)))
	return append(out, context...)
}

func segmentAAD(base []byte, index uint32, final bool) []byte {
	out := make([]byte, len(base), len(base)+5)
	copy(out, base)
	out = binary.BigEndian.AppendUint32(out, index)
	if final {
		return append(out, 1)
	}
	return append(out, 0)
}

// StreamEncryptor seals a stream incrementally: Header, then Update per input piece, then Finalize.
type StreamEncryptor struct {
	aead    cipher.AEAD
	hdr     []byte
	aad     []byte
	chunk   int
	buf     []byte
	counter uint64
	done    bool
}

func NewStreamEncryptor(key, context []byte, chunk int) (*StreamEncryptor, error) {
	if chunk < MinChunk || chunk > MaxChunk {
		return nil, errs.Config("chunk size out of bounds")
	}
	aead, err := newAEAD(key)
	if err != nil {
		return nil, err
	}
	h := header(chunk)
	return &StreamEncryptor{aead: aead, hdr: h, aad: bind(h, context), chunk: chunk}, nil
}

func (e *StreamEncryptor) Header() []byte { return append([]byte(nil), e.hdr...) }

func (e *StreamEncryptor) Update(p []byte) ([]byte, error) {
	if e.done {
		return nil, errs.Config("encryptor already finalized")
	}
	e.buf = append(e.buf, p...)
	var out []byte
	// Strictly greater-than: the last full segment must wait for Finalize to be marked final.
	for len(e.buf) > e.chunk {
		seg, err := e.seal(e.buf[:e.chunk], false)
		if err != nil {
			return nil, err
		}
		out = append(out, seg...)
		e.buf = e.buf[e.chunk:]
	}
	if len(e.buf) == 0 {
		e.buf = nil
	}
	return out, nil
}

func (e *StreamEncryptor) Finalize() ([]byte, error) {
	if e.done {
		return nil, errs.Config("encryptor already finalized")
	}
	e.done = true
	out, err := e.seal(e.buf, true)
	e.buf = nil
	return out, err
}

func (e *StreamEncryptor) seal(piece []byte, final bool) ([]byte, error) {
	if e.counter > maxChunks {
		return nil, errs.Invalid("object too large for one data key")
	}
	out := e.aead.Seal(nil, nil, piece, segmentAAD(e.aad, uint32(e.counter), final))
	e.counter++
	return out, nil
}

// StreamDecryptor opens a stream incrementally. Plaintext from non-final segments is released as each
// segment authenticates; truncation is only detectable at Finalize.
type StreamDecryptor struct {
	context []byte
	aead    cipher.AEAD
	aad     []byte
	chunk   int
	buf     []byte
	counter uint64
	started bool
	done    bool
}

func NewStreamDecryptor(key, context []byte) (*StreamDecryptor, error) {
	aead, err := newAEAD(key)
	if err != nil {
		return nil, err
	}
	return &StreamDecryptor{context: context, aead: aead}, nil
}

func (d *StreamDecryptor) Update(p []byte) ([]byte, error) {
	if d.done {
		return nil, errs.Integrity("data after end of ciphertext")
	}
	d.buf = append(d.buf, p...)
	if !d.started {
		if len(d.buf) < HeaderBytes {
			return nil, nil
		}
		h := append([]byte(nil), d.buf[:HeaderBytes]...)
		chunk, err := parseHeader(h)
		if err != nil {
			return nil, err
		}
		d.chunk, d.aad, d.started = chunk, bind(h, d.context), true
		d.buf = d.buf[HeaderBytes:]
	}
	ct := d.chunk + ChunkOverhead
	var out []byte
	for len(d.buf) > ct {
		pt, err := d.open(d.buf[:ct], false)
		if err != nil {
			return nil, err
		}
		out = append(out, pt...)
		d.buf = d.buf[ct:]
	}
	return out, nil
}

func (d *StreamDecryptor) Finalize() ([]byte, error) {
	if d.done {
		return nil, errs.Integrity("ciphertext already finalized")
	}
	d.done = true
	if !d.started || len(d.buf) < ChunkOverhead {
		return nil, errs.Integrity("ciphertext truncated")
	}
	return d.open(d.buf, true)
}

func (d *StreamDecryptor) open(seg []byte, final bool) ([]byte, error) {
	pt, err := d.aead.Open(nil, nil, seg, segmentAAD(d.aad, uint32(d.counter), final))
	d.counter++
	if err != nil {
		return nil, errs.Integrity("ciphertext failed authentication (tampered, truncated, reordered, or wrong context)")
	}
	return pt, nil
}

// DecryptingReader adapts a ciphertext reader into a plaintext reader.
type DecryptingReader struct {
	src     io.Reader
	dec     *StreamDecryptor
	pending []byte
	eof     bool
	scratch []byte
}

func NewDecryptingReader(src io.Reader, key, context []byte) (*DecryptingReader, error) {
	dec, err := NewStreamDecryptor(key, context)
	if err != nil {
		return nil, err
	}
	return &DecryptingReader{src: src, dec: dec, scratch: make([]byte, 256*1024)}, nil
}

func (r *DecryptingReader) Read(p []byte) (int, error) {
	for len(r.pending) == 0 {
		if r.eof {
			return 0, io.EOF
		}
		n, err := r.src.Read(r.scratch)
		if n > 0 {
			pt, derr := r.dec.Update(r.scratch[:n])
			if derr != nil {
				return 0, derr
			}
			r.pending = pt
		}
		if err == io.EOF {
			tail, ferr := r.dec.Finalize()
			if ferr != nil {
				return 0, ferr
			}
			r.pending = append(r.pending, tail...)
			r.eof = true
		} else if err != nil {
			return 0, err
		}
	}
	n := copy(p, r.pending)
	r.pending = r.pending[n:]
	return n, nil
}

// Seal is one-shot AES-256-GCM: version(1) | nonce(12) | ciphertext+tag.
func Seal(key, plaintext, aad []byte) ([]byte, error) {
	aead, err := newAEAD(key)
	if err != nil {
		return nil, err
	}
	return append([]byte{sealVersion}, aead.Seal(nil, nil, plaintext, aad)...), nil
}

func Open(key, sealed, aad []byte) ([]byte, error) {
	if len(sealed) < 1+ChunkOverhead || sealed[0] != sealVersion {
		return nil, errs.Integrity("malformed sealed value")
	}
	aead, err := newAEAD(key)
	if err != nil {
		return nil, err
	}
	pt, err := aead.Open(nil, nil, sealed[1:], aad)
	if err != nil {
		return nil, errs.Integrity("sealed value failed authentication")
	}
	return pt, nil
}
