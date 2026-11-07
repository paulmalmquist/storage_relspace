"""Authenticated encryption primitives (AES-256-GCM only: FIPS-approved, NIST SP 800-38D).

Two formats:

* **Stream** (blobs): segmented AES-256-GCM in the STREAM construction (Hoang et al., also used by
  Tink and age). Each fixed-size chunk is sealed with nonce = prefix(7) || counter(4) || last(1),
  and every chunk authenticates the header plus the caller's context. That makes chunk reordering,
  truncation, extension and cross-object substitution all fail authentication, while memory stays
  O(chunk_size) for multi-GB objects.

* **Sealed** (records, metadata, local key wrapping): one-shot AES-256-GCM with a random 96-bit
  nonce. Callers bound the number of seals per key via data-key rotation (well under the 2^32
  invocations NIST allows for random nonces).

Header layout (17 bytes):  magic "SBX1" | version u8 | algorithm u8 | chunk_size u32 | nonce_prefix[7]
"""

from __future__ import annotations

import secrets
import struct
from collections.abc import Iterable, Iterator
from dataclasses import dataclass

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from strongbox.errors import IntegrityViolation

KEY_BYTES = 32
TAG_BYTES = 16
NONCE_BYTES = 12
NONCE_PREFIX_BYTES = 7
MAGIC = b"SBX1"
FORMAT_VERSION = 1
ALG_AES256_GCM_STREAM = 1
MIN_CHUNK = 4 * 1024
MAX_CHUNK = 4 * 1024 * 1024
MAX_CHUNKS = 2**32 - 1

_HEADER = struct.Struct("!4sBBI7s")
HEADER_BYTES = _HEADER.size

SEAL_VERSION = 1


def new_data_key() -> bytes:
    """A fresh 256-bit data encryption key from the OS CSPRNG."""
    return secrets.token_bytes(KEY_BYTES)


def _check_key(key: bytes) -> None:
    if len(key) != KEY_BYTES:
        raise ValueError("AES-256 keys must be 32 bytes")


def _bind(header: bytes, context: bytes) -> bytes:
    # Length-prefixing the context keeps (header, context) pairs unambiguous.
    return header + struct.pack("!I", len(context)) + context


@dataclass(frozen=True, slots=True)
class StreamHeader:
    chunk_size: int
    nonce_prefix: bytes

    def to_bytes(self) -> bytes:
        return _HEADER.pack(MAGIC, FORMAT_VERSION, ALG_AES256_GCM_STREAM, self.chunk_size, self.nonce_prefix)

    @classmethod
    def parse(cls, raw: bytes) -> StreamHeader:
        if len(raw) != HEADER_BYTES:
            raise IntegrityViolation("truncated ciphertext header")
        magic, version, alg, chunk_size, prefix = _HEADER.unpack(raw)
        if magic != MAGIC or version != FORMAT_VERSION or alg != ALG_AES256_GCM_STREAM:
            raise IntegrityViolation("unrecognized ciphertext format")
        if not MIN_CHUNK <= chunk_size <= MAX_CHUNK:
            raise IntegrityViolation("ciphertext chunk size out of bounds")
        return cls(chunk_size=chunk_size, nonce_prefix=prefix)


class StreamEncryptor:
    """Incremental encryptor: ``header()``, then ``update()`` per input piece, then ``finalize()``."""

    def __init__(self, key: bytes, context: bytes, chunk_size: int) -> None:
        _check_key(key)
        if not MIN_CHUNK <= chunk_size <= MAX_CHUNK:
            raise ValueError("chunk_size out of bounds")
        self._aead = AESGCM(key)
        self._header = StreamHeader(chunk_size, secrets.token_bytes(NONCE_PREFIX_BYTES))
        self._header_bytes = self._header.to_bytes()
        self._aad = _bind(self._header_bytes, context)
        self._chunk = chunk_size
        self._buf = bytearray()
        self._counter = 0
        self._done = False

    def header(self) -> bytes:
        return self._header_bytes

    def update(self, data: bytes) -> bytes:
        if self._done:
            raise RuntimeError("encryptor already finalized")
        self._buf += data
        out = bytearray()
        # Strictly greater-than: the last full chunk must wait for finalize() to be marked final.
        while len(self._buf) > self._chunk:
            piece = bytes(self._buf[: self._chunk])
            del self._buf[: self._chunk]
            out += self._seal(piece, final=False)
        return bytes(out)

    def finalize(self) -> bytes:
        if self._done:
            raise RuntimeError("encryptor already finalized")
        self._done = True
        out = self._seal(bytes(self._buf), final=True)
        self._buf.clear()
        return out

    def _seal(self, piece: bytes, *, final: bool) -> bytes:
        if self._counter > MAX_CHUNKS:
            raise ValueError("object too large for one data key")
        nonce = self._header.nonce_prefix + struct.pack("!I", self._counter) + (b"\x01" if final else b"\x00")
        self._counter += 1
        return self._aead.encrypt(nonce, piece, self._aad)


class StreamDecryptor:
    """Incremental decryptor. Feed ciphertext in arbitrary pieces; ``finalize()`` checks the final chunk.

    Plaintext from non-final chunks is released as soon as each chunk authenticates. Truncation is only
    detectable at ``finalize()``, so consumers that must not act on a partial object should buffer.
    """

    def __init__(self, key: bytes, context: bytes) -> None:
        _check_key(key)
        self._aead = AESGCM(key)
        self._context = context
        self._header: StreamHeader | None = None
        self._aad = b""
        self._buf = bytearray()
        self._counter = 0
        self._done = False

    def update(self, data: bytes) -> bytes:
        if self._done:
            raise IntegrityViolation("data after end of ciphertext")
        self._buf += data
        if self._header is None:
            if len(self._buf) < HEADER_BYTES:
                return b""
            raw = bytes(self._buf[:HEADER_BYTES])
            del self._buf[:HEADER_BYTES]
            self._header = StreamHeader.parse(raw)
            self._aad = _bind(raw, self._context)
        ct_chunk = self._header.chunk_size + TAG_BYTES
        out = bytearray()
        while len(self._buf) > ct_chunk:
            piece = bytes(self._buf[:ct_chunk])
            del self._buf[:ct_chunk]
            out += self._open(piece, final=False)
        return bytes(out)

    def finalize(self) -> bytes:
        if self._done:
            raise IntegrityViolation("ciphertext already finalized")
        self._done = True
        if self._header is None or len(self._buf) < TAG_BYTES:
            raise IntegrityViolation("ciphertext truncated")
        out = self._open(bytes(self._buf), final=True)
        self._buf.clear()
        return out

    def _open(self, piece: bytes, *, final: bool) -> bytes:
        if self._header is None:
            raise IntegrityViolation("ciphertext header missing")
        nonce = self._header.nonce_prefix + struct.pack("!I", self._counter) + (b"\x01" if final else b"\x00")
        self._counter += 1
        try:
            return self._aead.decrypt(nonce, piece, self._aad)
        except InvalidTag as exc:
            raise IntegrityViolation(
                "ciphertext failed authentication (tampered, truncated, reordered, or wrong context)"
            ) from exc


def encrypt_stream(key: bytes, context: bytes, chunks: Iterable[bytes], chunk_size: int) -> Iterator[bytes]:
    enc = StreamEncryptor(key, context, chunk_size)
    yield enc.header()
    for chunk in chunks:
        out = enc.update(chunk)
        if out:
            yield out
    yield enc.finalize()


def decrypt_stream(key: bytes, context: bytes, chunks: Iterable[bytes]) -> Iterator[bytes]:
    dec = StreamDecryptor(key, context)
    for chunk in chunks:
        out = dec.update(chunk)
        if out:
            yield out
    tail = dec.finalize()
    if tail:
        yield tail


def seal(key: bytes, plaintext: bytes, aad: bytes) -> bytes:
    """One-shot AES-256-GCM. Output: version(1) | nonce(12) | ciphertext+tag."""
    _check_key(key)
    nonce = secrets.token_bytes(NONCE_BYTES)
    return bytes([SEAL_VERSION]) + nonce + AESGCM(key).encrypt(nonce, plaintext, aad)


def open_sealed(key: bytes, sealed: bytes, aad: bytes) -> bytes:
    _check_key(key)
    if len(sealed) < 1 + NONCE_BYTES + TAG_BYTES or sealed[0] != SEAL_VERSION:
        raise IntegrityViolation("malformed sealed value")
    nonce, body = sealed[1 : 1 + NONCE_BYTES], sealed[1 + NONCE_BYTES :]
    try:
        return AESGCM(key).decrypt(nonce, body, aad)
    except InvalidTag as exc:
        raise IntegrityViolation("sealed value failed authentication") from exc
