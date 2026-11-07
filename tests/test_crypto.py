from __future__ import annotations

import os
import struct
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import google_crc32c
import pytest

from strongbox.crypto.envelope import (
    HEADER_BYTES,
    TAG_BYTES,
    StreamHeader,
    decrypt_stream,
    encrypt_stream,
    new_data_key,
    open_sealed,
    seal,
)
from strongbox.crypto.fips import fips_status
from strongbox.crypto.kms import GcpKmsKeyProvider, LocalKeyProvider, WrappedKey
from strongbox.errors import ConfigurationError, IntegrityViolation

CHUNK = 4096


def _enc(key: bytes, pt: bytes, ctx: bytes = b"ctx", piece: int = 1000) -> bytes:
    pieces = [pt[i : i + piece] for i in range(0, len(pt), piece)] or [b""]
    return b"".join(encrypt_stream(key, ctx, pieces, CHUNK))


def _dec(key: bytes, ct: bytes, ctx: bytes = b"ctx", piece: int = 777) -> bytes:
    return b"".join(decrypt_stream(key, ctx, [ct[i : i + piece] for i in range(0, len(ct), piece)]))


@pytest.mark.parametrize("size", [0, 1, CHUNK - 1, CHUNK, CHUNK + 1, 3 * CHUNK, 50_000])
def test_stream_roundtrip(size: int) -> None:
    key, pt = new_data_key(), os.urandom(size)
    ct = _enc(key, pt)
    n_chunks = max(1, -(-size // CHUNK))
    assert len(ct) == HEADER_BYTES + size + n_chunks * TAG_BYTES
    assert _dec(key, ct) == pt


def test_ciphertext_does_not_contain_plaintext() -> None:
    pt = b"TERRAN-R-INJECTOR-GEOMETRY " * 500
    assert b"INJECTOR" not in _enc(new_data_key(), pt)


def test_bit_flip_detected() -> None:
    key = new_data_key()
    ct = bytearray(_enc(key, os.urandom(10_000)))
    ct[HEADER_BYTES + 5000] ^= 0x01
    with pytest.raises(IntegrityViolation):
        _dec(key, bytes(ct))


def test_truncation_at_chunk_boundary_detected() -> None:
    key = new_data_key()
    ct = _enc(key, os.urandom(3 * CHUNK + 10))
    truncated = ct[: HEADER_BYTES + 2 * (CHUNK + TAG_BYTES)]  # drop the final chunk entirely
    with pytest.raises(IntegrityViolation):
        _dec(key, truncated)


def test_extension_detected() -> None:
    key = new_data_key()
    ct = _enc(key, os.urandom(CHUNK * 2))
    with pytest.raises(IntegrityViolation):
        _dec(key, ct + ct[HEADER_BYTES : HEADER_BYTES + CHUNK + TAG_BYTES])


def test_chunk_reorder_detected() -> None:
    key = new_data_key()
    ct = _enc(key, os.urandom(3 * CHUNK + 1))
    body = ct[HEADER_BYTES:]
    c = CHUNK + TAG_BYTES
    swapped = ct[:HEADER_BYTES] + body[c : 2 * c] + body[:c] + body[2 * c :]
    with pytest.raises(IntegrityViolation):
        _dec(key, swapped)


def test_wrong_context_detected() -> None:
    key = new_data_key()
    ct = _enc(key, b"data", ctx=b"strongbox/blob/v1|blb_a|CUI//SP-EXPT")
    with pytest.raises(IntegrityViolation):
        _dec(key, ct, ctx=b"strongbox/blob/v1|blb_a|UNCONTROLLED")


def test_header_bounds_enforced() -> None:
    bad = struct.pack("!4sBBI7s", b"SBX1", 1, 1, 1 << 30, b"\x00" * 7)
    with pytest.raises(IntegrityViolation):
        StreamHeader.parse(bad)


def test_seal_roundtrip_and_aad() -> None:
    key = new_data_key()
    sealed = seal(key, b"secret", b"aad-1")
    assert open_sealed(key, sealed, b"aad-1") == b"secret"
    with pytest.raises(IntegrityViolation):
        open_sealed(key, sealed, b"aad-2")
    with pytest.raises(IntegrityViolation):
        open_sealed(new_data_key(), sealed, b"aad-1")


def test_local_kms_wrap_rotation(tmp_path: Path) -> None:
    path = tmp_path / "kr.json"
    LocalKeyProvider.create(path)
    assert oct(path.stat().st_mode & 0o777) == "0o600"
    dek = new_data_key()
    w1 = LocalKeyProvider(path).wrap(dek, b"ctx")
    LocalKeyProvider.rotate(path)
    kms = LocalKeyProvider(path)
    w2 = kms.wrap(dek, b"ctx")
    assert w1.kek_id == "local:k1"
    assert w2.kek_id == "local:k2"
    assert kms.unwrap(w1, b"ctx") == dek  # old KEKs still decrypt
    with pytest.raises(IntegrityViolation):
        kms.unwrap(w1, b"other-ctx")


class FakeKms:
    """Stands in for google.cloud.kms_v1.KeyManagementServiceClient."""

    def __init__(self, key_name: str, *, corrupt: bool = False) -> None:
        self.key_name = key_name
        self.version = key_name + "/cryptoKeyVersions/3"
        self.kek = new_data_key()
        self.corrupt = corrupt

    def encrypt(self, request: dict[str, Any]) -> Any:
        assert request["name"] == self.key_name
        assert google_crc32c.value(request["plaintext"]) == request["plaintext_crc32c"]
        ct = seal(self.kek, request["plaintext"], request["additional_authenticated_data"])
        crc = google_crc32c.value(ct) + (1 if self.corrupt else 0)
        return SimpleNamespace(
            name=self.version,
            ciphertext=ct,
            ciphertext_crc32c=crc,
            verified_plaintext_crc32c=True,
            verified_additional_authenticated_data_crc32c=True,
        )

    def decrypt(self, request: dict[str, Any]) -> Any:
        assert request["name"] == self.key_name
        pt = open_sealed(self.kek, request["ciphertext"], request["additional_authenticated_data"])
        return SimpleNamespace(plaintext=pt, plaintext_crc32c=google_crc32c.value(pt))


KEY = "projects/p/locations/us-east4/keyRings/strongbox/cryptoKeys/data"


def test_gcp_kms_wrap_unwrap() -> None:
    kms = GcpKmsKeyProvider(KEY, client=FakeKms(KEY))
    dek = new_data_key()
    wrapped = kms.wrap(dek, b"ctx")
    assert wrapped.kek_id == f"gcpkms:{KEY}/cryptoKeyVersions/3"
    assert kms.unwrap(wrapped, b"ctx") == dek


def test_gcp_kms_detects_corruption_in_transit() -> None:
    kms = GcpKmsKeyProvider(KEY, client=FakeKms(KEY, corrupt=True))
    with pytest.raises(IntegrityViolation):
        kms.wrap(new_data_key(), b"ctx")


def test_gcp_kms_refuses_foreign_key() -> None:
    kms = GcpKmsKeyProvider(KEY, client=FakeKms(KEY))
    other = WrappedKey("gcpkms:projects/evil/locations/x/keyRings/r/cryptoKeys/k/cryptoKeyVersions/1", b"x")
    with pytest.raises(IntegrityViolation):
        kms.unwrap(other, b"ctx")
    with pytest.raises(IntegrityViolation):
        kms.unwrap(WrappedKey("local:k1", b"x"), b"ctx")


def test_gcp_kms_validates_key_name() -> None:
    with pytest.raises(ConfigurationError):
        GcpKmsKeyProvider("not-a-key", client=object())


def test_fips_status_reports() -> None:
    status = fips_status()
    assert "openssl" in status
    assert isinstance(status["fips_enabled"], bool)
