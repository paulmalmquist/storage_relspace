"""Blob storage: per-object data keys, streaming AES-256-GCM, sealed metadata, crypto-shredding."""

from __future__ import annotations

import hashlib
import itertools
import json
import re
from collections.abc import Iterator
from dataclasses import dataclass
from datetime import datetime, timedelta
from types import TracebackType
from typing import Any

from sqlalchemy import delete, insert, select, update
from sqlalchemy.exc import IntegrityError

from strongbox.auth.policy import Action
from strongbox.crypto.envelope import StreamEncryptor, decrypt_stream, new_data_key
from strongbox.crypto.kms import KeyProvider, WrappedKey
from strongbox.errors import ContentWithheld, IntegrityViolation, NotFound, PayloadTooLarge, ValidationFailed
from strongbox.markings import Marking
from strongbox.services.guard import Ctx, Guard
from strongbox.services.keys import Sealer
from strongbox.services.paging import before_cursor, clamp_limit, encode_cursor
from strongbox.storage import schema
from strongbox.storage.blobstore import BlobBackend, BlobWriter
from strongbox.storage.database import Database, as_utc, new_id, utcnow

META_SCOPE = "blobmeta"
_MIME_PART = r"[A-Za-z0-9][A-Za-z0-9!#$&^_.+-]{0,126}"
_CONTENT_TYPE_RE = re.compile(rf"^{_MIME_PART}/{_MIME_PART}(\s*;\s*[A-Za-z0-9_.-]+=[^;\s]{{1,64}}){{0,3}}$")


def _ctx(kind: str, blob_id: str, marking: Marking) -> bytes:
    return f"strongbox/{kind}/v1|{blob_id}|{marking.banner}".encode()


@dataclass(frozen=True, slots=True)
class BlobMeta:
    id: str
    marking: Marking
    content_type: str
    size_bytes: int | None
    filename: str | None
    metadata: dict[str, Any]
    state: str
    created_by: str
    created_at: datetime

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "marking": self.marking.banner,
            "content_type": self.content_type,
            "size_bytes": self.size_bytes,
            "filename": self.filename,
            "metadata": self.metadata,
            "state": self.state,
            "created_by": self.created_by,
            "created_at": as_utc(self.created_at).isoformat(),
        }


class BlobUpload:
    """An in-progress upload. Use as a context manager: an exception aborts and cleans up."""

    def __init__(
        self,
        svc: BlobService,
        ctx: Ctx,
        blob_id: str,
        marking: Marking,
        dek: bytes,
        writer: BlobWriter,
        idempotency_key: str | None,
    ) -> None:
        self._svc, self._ctx, self.blob_id, self._marking = svc, ctx, blob_id, marking
        self._writer = writer
        self._idem = idempotency_key
        self._enc = StreamEncryptor(dek, _ctx("blob", blob_id, marking), svc.chunk_size)
        self._sha = hashlib.sha256()
        self._size = 0
        self._open = True
        self._emit(self._enc.header())

    def _emit(self, ct: bytes) -> None:
        if ct:
            self._sha.update(ct)
            self._writer.write(ct)

    def write(self, data: bytes) -> None:
        if not self._open:
            raise RuntimeError("upload is closed")
        self._size += len(data)
        if self._size > self._svc.max_blob_bytes:
            self.abort("size limit exceeded")
            raise PayloadTooLarge(f"blob exceeds {self._svc.max_blob_bytes} bytes")
        self._emit(self._enc.update(data))

    def commit(self) -> BlobMeta:
        if not self._open:
            raise RuntimeError("upload is closed")
        self._emit(self._enc.finalize())
        self._writer.commit()
        self._open = False
        with self._svc.db.engine.begin() as conn:
            conn.execute(
                update(schema.blobs)
                .where(schema.blobs.c.id == self.blob_id)
                .values(state="active", size_bytes=self._size, ciphertext_sha256=self._sha.hexdigest())
            )
            if self._idem:
                try:
                    with conn.begin_nested():
                        conn.execute(
                            insert(schema.idempotency_keys).values(
                                principal=self._ctx.principal.subject,
                                key=self._idem,
                                resource_type="blob",
                                resource_id=self.blob_id,
                                created_at=utcnow(),
                            )
                        )
                except IntegrityError:
                    pass  # a concurrent retry won the race; both objects are valid and audited
        self._svc.guard.note(
            self._ctx,
            Action.BLOB_CREATE,
            resource_type="blob",
            resource_id=self.blob_id,
            decision="allow",
            reason="blob stored",
            marking=self._marking,
            details={"size_bytes": self._size},
        )
        return self._svc._load_meta(self.blob_id)

    def abort(self, reason: str = "aborted") -> None:
        if not self._open:
            return
        self._open = False
        try:
            self._writer.abort()
        finally:
            with self._svc.db.engine.begin() as conn:
                conn.execute(delete(schema.blobs).where(schema.blobs.c.id == self.blob_id))
            self._svc.guard.note(
                self._ctx,
                Action.BLOB_CREATE,
                resource_type="blob",
                resource_id=self.blob_id,
                decision="error",
                reason=f"upload aborted: {reason}"[:200],
                marking=self._marking,
            )

    def __enter__(self) -> BlobUpload:
        return self

    def __exit__(
        self, exc_type: type[BaseException] | None, exc: BaseException | None, tb: TracebackType | None
    ) -> None:
        if exc_type is not None:
            self.abort(exc_type.__name__)


class BlobService:
    def __init__(
        self,
        db: Database,
        backend: BlobBackend,
        kms: KeyProvider,
        sealer: Sealer,
        guard: Guard,
        *,
        chunk_size: int,
        max_blob_bytes: int,
        max_metadata_bytes: int,
    ) -> None:
        self.db = db
        self.backend = backend
        self.kms = kms
        self.sealer = sealer
        self.guard = guard
        self.chunk_size = chunk_size
        self.max_blob_bytes = max_blob_bytes
        self.max_metadata_bytes = max_metadata_bytes

    # ---- create -------------------------------------------------------------------------
    def begin_upload(
        self,
        ctx: Ctx,
        *,
        marking: Marking,
        content_type: str = "application/octet-stream",
        filename: str | None = None,
        metadata: dict[str, Any] | None = None,
        idempotency_key: str | None = None,
        declared_size: int | None = None,
    ) -> BlobUpload | BlobMeta:
        self._validate(content_type, filename, metadata, idempotency_key)
        self.guard.check(
            ctx,
            Action.BLOB_CREATE,
            resource_type="blob",
            resource_id=None,
            marking=marking,
            audit_allow=False,
            concealable=False,
        )
        if declared_size is not None and declared_size > self.max_blob_bytes:
            raise PayloadTooLarge(f"blob exceeds {self.max_blob_bytes} bytes")
        if idempotency_key:
            existing = self._idempotent(ctx, idempotency_key)
            if existing:
                return self.get_meta(ctx, existing)

        blob_id = new_id("blb")
        dek = new_data_key()
        wrapped = self.kms.wrap(dek, _ctx("blob-dek", blob_id, marking))
        meta_key_id, sealed_meta = self.sealer.seal_json(
            META_SCOPE,
            _ctx("blob-meta", blob_id, marking),
            {"filename": filename, "metadata": metadata or {}},
        )
        with self.db.engine.begin() as conn:
            conn.execute(
                insert(schema.blobs).values(
                    id=blob_id,
                    state="pending",
                    marking=marking.banner,
                    content_type=content_type,
                    chunk_size=self.chunk_size,
                    kek_id=wrapped.kek_id,
                    wrapped_dek=wrapped.ciphertext,
                    meta_key_id=meta_key_id,
                    sealed_meta=sealed_meta,
                    storage_key=blob_id,
                    created_by=ctx.principal.subject,
                    created_at=utcnow(),
                )
            )
        try:
            writer = self.backend.open_writer(blob_id)
        except Exception:
            with self.db.engine.begin() as conn:
                conn.execute(delete(schema.blobs).where(schema.blobs.c.id == blob_id))
            raise
        return BlobUpload(self, ctx, blob_id, marking, dek, writer, idempotency_key)

    def put_bytes(self, ctx: Ctx, data: bytes, **kwargs: Any) -> BlobMeta:
        upload = self.begin_upload(ctx, declared_size=len(data), **kwargs)
        if isinstance(upload, BlobMeta):
            return upload
        with upload:
            upload.write(data)
            return upload.commit()

    def _validate(
        self,
        content_type: str,
        filename: str | None,
        metadata: dict[str, Any] | None,
        idempotency_key: str | None,
    ) -> None:
        if not _CONTENT_TYPE_RE.match(content_type or ""):
            raise ValidationFailed("invalid content type")
        if filename is not None and (len(filename) > 255 or any(c in filename for c in "\x00/\\")):
            raise ValidationFailed("filename must be <= 255 characters without path separators")
        if metadata is not None:
            if not isinstance(metadata, dict) or not all(isinstance(k, str) for k in metadata):
                raise ValidationFailed("metadata must be a JSON object")
            if len(json.dumps(metadata)) > self.max_metadata_bytes:
                raise ValidationFailed(f"metadata exceeds {self.max_metadata_bytes} bytes")
        if idempotency_key is not None and not 1 <= len(idempotency_key) <= 255:
            raise ValidationFailed("idempotency key must be 1-255 characters")

    def _idempotent(self, ctx: Ctx, key: str) -> str | None:
        with self.db.engine.connect() as conn:
            row = conn.execute(
                select(schema.idempotency_keys.c.resource_id).where(
                    schema.idempotency_keys.c.principal == ctx.principal.subject,
                    schema.idempotency_keys.c.resource_type == "blob",
                    schema.idempotency_keys.c.key == key,
                )
            ).first()
        return row.resource_id if row else None

    # ---- read ---------------------------------------------------------------------------
    def _row(self, blob_id: str, states: tuple[str, ...] = ("active",)) -> Any:
        with self.db.engine.connect() as conn:
            row = conn.execute(select(schema.blobs).where(schema.blobs.c.id == blob_id)).first()
        if row is None or row.state not in states:
            raise NotFound("blob not found")
        return row

    def _meta(self, row: Any) -> BlobMeta:
        marking = Marking.parse(row.marking)
        sealed = self.sealer.open_json(
            META_SCOPE, row.meta_key_id, _ctx("blob-meta", row.id, marking), bytes(row.sealed_meta)
        )
        return BlobMeta(
            id=row.id,
            marking=marking,
            content_type=row.content_type,
            size_bytes=row.size_bytes,
            filename=sealed.get("filename"),
            metadata=sealed.get("metadata") or {},
            state=row.state,
            created_by=row.created_by,
            created_at=row.created_at,
        )

    def _load_meta(self, blob_id: str) -> BlobMeta:
        return self._meta(self._row(blob_id))

    def get_meta(self, ctx: Ctx, blob_id: str) -> BlobMeta:
        row = self._row(blob_id)
        self.guard.check(
            ctx,
            Action.BLOB_READ_META,
            resource_type="blob",
            resource_id=blob_id,
            marking=Marking.parse(row.marking),
        )
        return self._meta(row)

    def open_content(self, ctx: Ctx, blob_id: str) -> tuple[BlobMeta, Iterator[bytes]]:
        """Authorize, then return metadata and a plaintext iterator.

        The first chunk is decrypted before returning, so a missing object, a wrong key or tampering in
        the first segment fails here rather than after a response has started.
        """
        row = self._row(blob_id)
        marking = Marking.parse(row.marking)
        decision = self.guard.check(
            ctx, Action.BLOB_READ_CONTENT, resource_type="blob", resource_id=blob_id, marking=marking
        )
        if decision.withheld:
            raise ContentWithheld(decision.reason)
        meta = self._meta(row)
        dek = self.kms.unwrap(
            WrappedKey(row.kek_id, bytes(row.wrapped_dek)), _ctx("blob-dek", blob_id, marking)
        )
        expected_sha = row.ciphertext_sha256

        def plaintext() -> Iterator[bytes]:
            sha = hashlib.sha256()

            def ciphertext() -> Iterator[bytes]:
                for piece in self.backend.read(row.storage_key):
                    sha.update(piece)
                    yield piece

            try:
                yield from decrypt_stream(dek, _ctx("blob", blob_id, marking), ciphertext())
                if expected_sha and sha.hexdigest() != expected_sha:
                    raise IntegrityViolation("stored ciphertext digest mismatch")
            except IntegrityViolation as exc:
                self.guard.note(
                    ctx,
                    Action.BLOB_READ_CONTENT,
                    resource_type="blob",
                    resource_id=blob_id,
                    decision="error",
                    reason=f"integrity failure: {exc.detail}",
                    marking=marking,
                )
                raise

        it = plaintext()
        first = next(it, None)
        return meta, itertools.chain([] if first is None else [first], it)

    def read_all(self, ctx: Ctx, blob_id: str) -> tuple[BlobMeta, bytes]:
        meta, it = self.open_content(ctx, blob_id)
        return meta, b"".join(it)

    def list(
        self, ctx: Ctx, *, limit: int | None = None, cursor: str | None = None
    ) -> tuple[list[BlobMeta], str | None]:
        self.guard.check(
            ctx, Action.BLOB_LIST, resource_type="blob", resource_id=None, marking=None, audit_allow=False
        )
        n = clamp_limit(limit)
        stmt = select(schema.blobs).where(schema.blobs.c.state == "active")
        cond = before_cursor(schema.blobs.c.created_at, schema.blobs.c.id, cursor)
        if cond is not None:
            stmt = stmt.where(cond)
        stmt = stmt.order_by(schema.blobs.c.created_at.desc(), schema.blobs.c.id.desc()).limit(n + 1)
        with self.db.engine.connect() as conn:
            rows = conn.execute(stmt).all()
        more = len(rows) > n
        rows = rows[:n]
        items = [
            self._meta(r)
            for r in rows
            if self.guard.peek(ctx, Action.BLOB_READ_META, Marking.parse(r.marking)).allowed
        ]
        self.guard.note(
            ctx,
            Action.BLOB_LIST,
            resource_type="blob",
            resource_id=None,
            decision="allow",
            reason="listed blobs",
            details={"returned": len(items), "scanned": len(rows)},
        )
        next_cursor = encode_cursor(rows[-1].created_at, rows[-1].id) if more and rows else None
        return items, next_cursor

    # ---- delete -------------------------------------------------------------------------
    def delete(self, ctx: Ctx, blob_id: str, *, shred: bool = False) -> None:
        """Soft delete keeps ciphertext for retention. Shred destroys the only copy of the wrapped data key
        and the object, which makes every copy of the ciphertext (including backups) unrecoverable."""
        row = self._row(blob_id, ("active", "deleted") if shred else ("active",))
        marking = Marking.parse(row.marking)
        action = Action.BLOB_SHRED if shred else Action.BLOB_DELETE
        self.guard.check(ctx, action, resource_type="blob", resource_id=blob_id, marking=marking)
        now = utcnow()
        if shred:
            with self.db.engine.begin() as conn:
                conn.execute(
                    update(schema.blobs)
                    .where(schema.blobs.c.id == blob_id)
                    .values(state="shredded", wrapped_dek=None, sealed_meta=b"", shredded_at=now)
                )
            self.backend.delete(row.storage_key)
        else:
            with self.db.engine.begin() as conn:
                conn.execute(
                    update(schema.blobs)
                    .where(schema.blobs.c.id == blob_id)
                    .values(state="deleted", deleted_at=now)
                )

    def sweep_pending(self, older_than_seconds: int = 3600) -> int:
        """Remove uploads abandoned by a crashed process."""
        cutoff = utcnow() - timedelta(seconds=older_than_seconds)
        with self.db.engine.connect() as conn:
            rows = conn.execute(
                select(schema.blobs.c.id, schema.blobs.c.storage_key).where(
                    schema.blobs.c.state == "pending", schema.blobs.c.created_at < cutoff
                )
            ).all()
        for r in rows:
            self.backend.delete(r.storage_key)
            with self.db.engine.begin() as conn:
                conn.execute(delete(schema.blobs).where(schema.blobs.c.id == r.id))
        return len(rows)
