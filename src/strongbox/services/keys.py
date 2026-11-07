"""Data-key management for small values (records, sealed metadata) and blind indexes.

Blobs get a fresh data key per object. Small values would cost one KMS round trip each that way,
so they use per-scope data keys instead: wrapped by the KEK, stored in ``data_keys``, unwrapped on
demand and cached in memory for a short TTL, and rotated on a schedule. Old keys stay available
for decryption. Blind-index keys never rotate, because tokens must stay comparable.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import threading
import time
from collections.abc import Callable
from datetime import timedelta
from typing import Any

from sqlalchemy import insert, select

from strongbox.crypto.envelope import new_data_key, open_sealed, seal
from strongbox.crypto.kms import KeyProvider, WrappedKey
from strongbox.errors import IntegrityViolation
from strongbox.storage import schema
from strongbox.storage.database import Database, as_utc, new_id, utcnow

PURPOSE_DATA = "data"
PURPOSE_INDEX = "index"


def _wrap_aad(key_id: str, scope: str, purpose: str) -> bytes:
    return f"strongbox/datakey/v1|{key_id}|{scope}|{purpose}".encode()


class DataKeyManager:
    def __init__(
        self,
        db: Database,
        kms: KeyProvider,
        *,
        rotation_seconds: int,
        cache_ttl_seconds: int,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self._db = db
        self._kms = kms
        self._rotation = timedelta(seconds=rotation_seconds)
        self._ttl = cache_ttl_seconds
        self._clock = clock
        self._cache: dict[str, tuple[bytes, float]] = {}
        self._lock = threading.Lock()

    def active_key(self, scope: str, purpose: str = PURPOSE_DATA) -> tuple[str, bytes]:
        with self._db.engine.connect() as conn:
            row = conn.execute(
                select(schema.data_keys)
                .where(
                    schema.data_keys.c.scope == scope,
                    schema.data_keys.c.purpose == purpose,
                    schema.data_keys.c.retired_at.is_(None),
                )
                .order_by(schema.data_keys.c.created_at.desc())
                .limit(1)
            ).first()
        if row is not None:
            fresh = utcnow() - as_utc(row.created_at) < self._rotation
            if fresh or purpose == PURPOSE_INDEX:
                return row.id, self.key(row.id)
        return self._create(scope, purpose)

    def _create(self, scope: str, purpose: str) -> tuple[str, bytes]:
        key_id = new_id("dk")
        dek = new_data_key()
        wrapped = self._kms.wrap(dek, _wrap_aad(key_id, scope, purpose))
        with self._db.engine.begin() as conn:
            conn.execute(
                insert(schema.data_keys).values(
                    id=key_id,
                    scope=scope,
                    purpose=purpose,
                    kek_id=wrapped.kek_id,
                    wrapped_key=wrapped.ciphertext,
                    created_at=utcnow(),
                )
            )
        self._remember(key_id, dek)
        return key_id, dek

    def key(self, key_id: str, *, expected_scope: str | None = None) -> bytes:
        now = self._clock()
        with self._lock:
            hit = self._cache.get(key_id)
            if hit and hit[1] > now and expected_scope is None:
                return hit[0]
        with self._db.engine.connect() as conn:
            row = conn.execute(select(schema.data_keys).where(schema.data_keys.c.id == key_id)).first()
        if row is None:
            raise IntegrityViolation(f"data key {key_id} not found")
        if expected_scope is not None and row.scope != expected_scope:
            raise IntegrityViolation("data key belongs to a different scope")
        if hit and hit[1] > now:
            return hit[0]
        dek = self._kms.unwrap(
            WrappedKey(row.kek_id, bytes(row.wrapped_key)), _wrap_aad(row.id, row.scope, row.purpose)
        )
        self._remember(key_id, dek)
        return dek

    def _remember(self, key_id: str, dek: bytes) -> None:
        with self._lock:
            self._cache[key_id] = (dek, self._clock() + self._ttl)

    def clear_cache(self) -> None:
        with self._lock:
            self._cache.clear()


class Sealer:
    """Seal JSON-serializable values under a scope's active data key."""

    def __init__(self, keys: DataKeyManager) -> None:
        self._keys = keys

    def seal_json(self, scope: str, aad: bytes, value: Any) -> tuple[str, bytes]:
        key_id, key = self._keys.active_key(scope)
        raw = json.dumps(value, separators=(",", ":"), sort_keys=True).encode()
        return key_id, seal(key, raw, aad)

    def open_json(self, scope: str, key_id: str, aad: bytes, sealed: bytes) -> Any:
        key = self._keys.key(key_id, expected_scope=scope)
        return json.loads(open_sealed(key, sealed, aad))


def canonical_scalar(value: Any) -> str:
    if value is not None and not isinstance(value, str | int | float | bool):
        raise ValueError("only scalar values (string, number, boolean, null) can be indexed or filtered")
    return json.dumps(value, separators=(",", ":"), ensure_ascii=False)


def blind_token(index_key: bytes, collection: str, field: str, value: Any) -> str:
    """HMAC-SHA-256 token: equality-searchable without revealing the value."""
    msg = f"{collection}\x1f{field}\x1f{canonical_scalar(value)}".encode()
    return "b:" + hmac.new(index_key, msg, hashlib.sha256).hexdigest()


def plain_token(value: Any) -> str:
    text = canonical_scalar(value)
    if len(text) <= 120:
        return "p:" + text
    return "h:" + hashlib.sha256(text.encode()).hexdigest()
