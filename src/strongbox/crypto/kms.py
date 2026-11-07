"""Key-encryption-key (KEK) providers for envelope encryption.

Data keys never leave the process unwrapped. They are wrapped by a KEK that lives in:

* ``GcpKmsKeyProvider`` - Cloud KMS. Use an HSM-protection-level key (FIPS 140 Level 3) in production.
  Wrapping requests carry additional authenticated data and are checked end to end with CRC32C,
  as Google recommends.
* ``LocalKeyProvider`` - a JSON keyring on disk, for development and tests only. Production mode
  refuses to start with it.

Both bind the wrap to caller-supplied AAD, so a wrapped key lifted from one object cannot be
unwrapped in the context of another.
"""

from __future__ import annotations

import base64
import json
import logging
import os
import re
import secrets
import stat
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Protocol

from strongbox.crypto.envelope import KEY_BYTES, open_sealed, seal
from strongbox.errors import ConfigurationError, IntegrityViolation

log = logging.getLogger(__name__)


@dataclass(frozen=True, slots=True)
class WrappedKey:
    kek_id: str
    ciphertext: bytes


class KeyProvider(Protocol):
    def wrap(self, plaintext_key: bytes, aad: bytes) -> WrappedKey: ...

    def unwrap(self, wrapped: WrappedKey, aad: bytes) -> bytes: ...

    def describe(self) -> dict[str, Any]: ...


# --------------------------------------------------------------------------------------------
# Local keyring (dev/test)
# --------------------------------------------------------------------------------------------
class LocalKeyProvider:
    PREFIX = "local:"

    def __init__(self, path: Path) -> None:
        self._path = Path(path)
        if not self._path.exists():
            raise ConfigurationError(
                f"local keyring not found at {self._path}; run `strongbox keyring create`"
            )
        mode = self._path.stat().st_mode
        if mode & (stat.S_IRWXG | stat.S_IRWXO):
            log.warning("local keyring %s is readable by group/other; chmod 600 it", self._path)
        data = json.loads(self._path.read_text())
        self._keys = {kid: base64.b64decode(v) for kid, v in data["keys"].items()}
        self._active = data["active"]
        if self._active not in self._keys or any(len(k) != KEY_BYTES for k in self._keys.values()):
            raise ConfigurationError("local keyring is malformed")

    @staticmethod
    def create(path: Path) -> str:
        path = Path(path)
        if path.exists():
            raise ConfigurationError(f"keyring already exists at {path}")
        path.parent.mkdir(parents=True, exist_ok=True)
        kid = "k1"
        LocalKeyProvider._write(path, {"active": kid, "keys": {kid: _b64(secrets.token_bytes(KEY_BYTES))}})
        return kid

    @staticmethod
    def rotate(path: Path) -> str:
        data = json.loads(Path(path).read_text())
        kid = f"k{len(data['keys']) + 1}"
        data["keys"][kid] = _b64(secrets.token_bytes(KEY_BYTES))
        data["active"] = kid
        LocalKeyProvider._write(Path(path), data)
        return kid

    @staticmethod
    def _write(path: Path, data: dict[str, Any]) -> None:
        tmp = path.with_suffix(".tmp")
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as fh:
            json.dump(data, fh)
        os.replace(tmp, path)

    def wrap(self, plaintext_key: bytes, aad: bytes) -> WrappedKey:
        return WrappedKey(self.PREFIX + self._active, seal(self._keys[self._active], plaintext_key, aad))

    def unwrap(self, wrapped: WrappedKey, aad: bytes) -> bytes:
        if not wrapped.kek_id.startswith(self.PREFIX):
            raise IntegrityViolation(f"key was wrapped by a different provider ({wrapped.kek_id})")
        kek = self._keys.get(wrapped.kek_id[len(self.PREFIX) :])
        if kek is None:
            raise IntegrityViolation(f"unknown key-encryption key {wrapped.kek_id}")
        return open_sealed(kek, wrapped.ciphertext, aad)

    def describe(self) -> dict[str, Any]:
        return {"provider": "local", "active_kek": self.PREFIX + self._active, "production_safe": False}


def _b64(raw: bytes) -> str:
    return base64.b64encode(raw).decode()


# --------------------------------------------------------------------------------------------
# Google Cloud KMS
# --------------------------------------------------------------------------------------------
_KEY_NAME_RE = re.compile(r"^projects/[^/]+/locations/[^/]+/keyRings/[^/]+/cryptoKeys/[^/]+$")


class GcpKmsKeyProvider:
    PREFIX = "gcpkms:"

    def __init__(self, key_name: str, client: Any | None = None) -> None:
        if not _KEY_NAME_RE.match(key_name):
            raise ConfigurationError("kms_key_name must be projects/*/locations/*/keyRings/*/cryptoKeys/*")
        self._key_name = key_name
        if client is None:
            try:
                from google.cloud import kms_v1
            except ImportError as exc:  # pragma: no cover - exercised only without the gcp extra
                raise ConfigurationError("install strongbox[gcp] to use Cloud KMS") from exc
            client = kms_v1.KeyManagementServiceClient()
        self._client = client

    @staticmethod
    def _crc(data: bytes) -> int:
        import google_crc32c

        return int(google_crc32c.value(data))

    def wrap(self, plaintext_key: bytes, aad: bytes) -> WrappedKey:
        resp = self._client.encrypt(
            request={
                "name": self._key_name,
                "plaintext": plaintext_key,
                "plaintext_crc32c": self._crc(plaintext_key),
                "additional_authenticated_data": aad,
                "additional_authenticated_data_crc32c": self._crc(aad),
            }
        )
        if not resp.verified_plaintext_crc32c or not resp.verified_additional_authenticated_data_crc32c:
            raise IntegrityViolation("Cloud KMS did not verify request integrity")
        if self._crc(resp.ciphertext) != int(resp.ciphertext_crc32c):
            raise IntegrityViolation("Cloud KMS response corrupted in transit")
        if not str(resp.name).startswith(self._key_name + "/cryptoKeyVersions/"):
            raise IntegrityViolation("Cloud KMS used an unexpected key")
        return WrappedKey(self.PREFIX + str(resp.name), bytes(resp.ciphertext))

    def unwrap(self, wrapped: WrappedKey, aad: bytes) -> bytes:
        if not wrapped.kek_id.startswith(self.PREFIX):
            raise IntegrityViolation(f"key was wrapped by a different provider ({wrapped.kek_id})")
        version = wrapped.kek_id[len(self.PREFIX) :]
        key_name = version.split("/cryptoKeyVersions/")[0]
        if key_name != self._key_name:
            raise IntegrityViolation("wrapped key belongs to a key outside this deployment")
        resp = self._client.decrypt(
            request={
                "name": key_name,
                "ciphertext": wrapped.ciphertext,
                "ciphertext_crc32c": self._crc(wrapped.ciphertext),
                "additional_authenticated_data": aad,
                "additional_authenticated_data_crc32c": self._crc(aad),
            }
        )
        plaintext = bytes(resp.plaintext)
        if self._crc(plaintext) != int(resp.plaintext_crc32c):
            raise IntegrityViolation("Cloud KMS response corrupted in transit")
        if len(plaintext) != KEY_BYTES:
            raise IntegrityViolation("unwrapped key has the wrong length")
        return plaintext

    def describe(self) -> dict[str, Any]:
        return {"provider": "gcp-kms", "key": self._key_name, "production_safe": True}
