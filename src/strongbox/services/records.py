"""Structured records in schema-validated collections.

Encrypted collections (mandatory for CUI) store each document sealed under the collection's data
key. The AAD binds collection, record id, marking and version, so swapping ciphertexts between rows,
rolling a row back, or editing its marking in the database all fail authentication.

Equality search on encrypted collections uses HMAC blind-index tokens over declared
``indexed_fields``. The trade-off: equal values produce equal tokens (frequency is visible to someone
with database access); range queries and full-text search are not supported on encrypted data.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from datetime import datetime
from typing import Any

from jsonschema import Draft202012Validator
from jsonschema.exceptions import SchemaError
from sqlalchemy import delete, insert, select, update
from sqlalchemy.exc import IntegrityError

from strongbox.auth.policy import Action
from strongbox.errors import Conflict, NotFound, PreconditionFailed, ValidationFailed
from strongbox.markings import Marking
from strongbox.services.guard import Ctx, Guard
from strongbox.services.keys import PURPOSE_INDEX, DataKeyManager, Sealer, blind_token, plain_token
from strongbox.services.paging import before_cursor, clamp_limit, encode_cursor
from strongbox.storage import schema
from strongbox.storage.database import Database, as_utc, new_id, utcnow

NAME_RE = re.compile(r"^[a-z][a-z0-9_]{1,62}$")
FIELD_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,63}$")
MAX_INDEXED_FIELDS = 16


def _scope(collection: str) -> str:
    return f"collection:{collection}"


def _aad(collection: str, record_id: str, marking: Marking, version: int) -> bytes:
    return f"strongbox/record/v1|{collection}|{record_id}|{marking.banner}|{version}".encode()


@dataclass(frozen=True, slots=True)
class Collection:
    name: str
    marking: Marking
    encrypted: bool
    indexed_fields: tuple[str, ...]
    json_schema: dict[str, Any]
    index_key_id: str | None
    version: int
    created_by: str
    created_at: datetime

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "marking": self.marking.banner,
            "encrypted": self.encrypted,
            "indexed_fields": list(self.indexed_fields),
            "json_schema": self.json_schema,
            "version": self.version,
            "created_by": self.created_by,
            "created_at": as_utc(self.created_at).isoformat(),
        }


@dataclass(frozen=True, slots=True)
class RecordView:
    id: str
    collection: str
    marking: Marking
    version: int
    data: dict[str, Any] | None
    content_withheld: bool
    created_by: str
    created_at: datetime
    updated_by: str
    updated_at: datetime
    withheld_reason: str | None = None

    def to_dict(self) -> dict[str, Any]:
        out = {
            "id": self.id,
            "collection": self.collection,
            "marking": self.marking.banner,
            "version": self.version,
            "data": self.data,
            "content_withheld": self.content_withheld,
            "created_by": self.created_by,
            "created_at": as_utc(self.created_at).isoformat(),
            "updated_by": self.updated_by,
            "updated_at": as_utc(self.updated_at).isoformat(),
        }
        if self.withheld_reason:
            out["withheld_reason"] = self.withheld_reason
        return out


def _request_hash(data: dict[str, Any], marking: Marking) -> str:
    raw = json.dumps({"d": data, "m": marking.banner}, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(raw.encode()).hexdigest()


class RecordService:
    def __init__(
        self, db: Database, keys: DataKeyManager, sealer: Sealer, guard: Guard, *, max_record_bytes: int
    ) -> None:
        self.db = db
        self.keys = keys
        self.sealer = sealer
        self.guard = guard
        self.max_record_bytes = max_record_bytes

    # ---- collections --------------------------------------------------------------------
    def create_collection(
        self,
        ctx: Ctx,
        *,
        name: str,
        marking: Marking,
        json_schema: dict[str, Any] | None = None,
        indexed_fields: list[str] | None = None,
        encrypted: bool | None = None,
    ) -> Collection:
        if not NAME_RE.match(name):
            raise ValidationFailed("collection name must match ^[a-z][a-z0-9_]{1,62}$")
        fields = list(dict.fromkeys(indexed_fields or []))
        if len(fields) > MAX_INDEXED_FIELDS or not all(FIELD_RE.match(f) for f in fields):
            raise ValidationFailed(f"indexed_fields: up to {MAX_INDEXED_FIELDS} top-level field names")
        schema_doc = json_schema or {"type": "object"}
        try:
            Draft202012Validator.check_schema(schema_doc)
        except SchemaError as exc:
            raise ValidationFailed(f"invalid JSON Schema: {exc.message}") from exc
        if schema_doc.get("type") not in (None, "object"):
            raise ValidationFailed("collection schema must describe a JSON object")
        enc = marking.controlled if encrypted is None else encrypted
        if marking.controlled and not enc:
            raise ValidationFailed("CUI collections must be encrypted")

        self.guard.check(
            ctx,
            Action.COLLECTION_CREATE,
            resource_type="collection",
            resource_id=name,
            marking=marking,
            concealable=False,
        )
        index_key_id = self.keys.active_key(_scope(name), PURPOSE_INDEX)[0] if enc and fields else None
        now = utcnow()
        try:
            with self.db.engine.begin() as conn:
                conn.execute(
                    insert(schema.collections).values(
                        name=name,
                        marking=marking.banner,
                        encrypted=enc,
                        indexed_fields=fields,
                        json_schema=schema_doc,
                        index_key_id=index_key_id,
                        version=1,
                        created_by=ctx.principal.subject,
                        created_at=now,
                        updated_at=now,
                    )
                )
        except IntegrityError as exc:
            raise Conflict(f"collection {name} already exists") from exc
        return self._collection(name)

    def _collection(self, name: str) -> Collection:
        with self.db.engine.connect() as conn:
            row = conn.execute(select(schema.collections).where(schema.collections.c.name == name)).first()
        if row is None:
            raise NotFound("collection not found")
        return Collection(
            name=row.name,
            marking=Marking.parse(row.marking),
            encrypted=bool(row.encrypted),
            indexed_fields=tuple(row.indexed_fields),
            json_schema=row.json_schema,
            index_key_id=row.index_key_id,
            version=row.version,
            created_by=row.created_by,
            created_at=row.created_at,
        )

    def get_collection(self, ctx: Ctx, name: str) -> Collection:
        coll = self._collection(name)
        self.guard.check(
            ctx, Action.COLLECTION_READ, resource_type="collection", resource_id=name, marking=coll.marking
        )
        return coll

    def list_collections(self, ctx: Ctx) -> list[Collection]:
        self.guard.check(
            ctx,
            Action.COLLECTION_READ,
            resource_type="collection",
            resource_id=None,
            marking=None,
            audit_allow=False,
        )
        with self.db.engine.connect() as conn:
            names = [r.name for r in conn.execute(select(schema.collections.c.name).order_by("name"))]
        out = [
            c
            for c in map(self._collection, names)
            if self.guard.peek(ctx, Action.COLLECTION_READ, c.marking).allowed
        ]
        self.guard.note(
            ctx,
            Action.COLLECTION_READ,
            resource_type="collection",
            resource_id=None,
            decision="allow",
            reason="listed collections",
            details={"returned": len(out)},
        )
        return out

    # ---- helpers ------------------------------------------------------------------------
    def _validate(self, coll: Collection, data: Any) -> dict[str, Any]:
        if not isinstance(data, dict):
            raise ValidationFailed("record data must be a JSON object")
        if len(json.dumps(data)) > self.max_record_bytes:
            raise ValidationFailed(f"record exceeds {self.max_record_bytes} bytes")
        errors = sorted(Draft202012Validator(coll.json_schema).iter_errors(data), key=lambda e: list(e.path))
        if errors:
            msgs = [f"{'/'.join(map(str, e.path)) or '<root>'}: {e.message}" for e in errors[:5]]
            raise ValidationFailed("schema validation failed: " + "; ".join(msgs))
        return data

    def _record_marking(self, coll: Collection, marking: Marking | None) -> Marking:
        m = marking or coll.marking
        if not m.dominates(coll.marking):
            raise ValidationFailed(
                f"record marking {m.banner} cannot be less restrictive than {coll.marking.banner}"
            )
        return m

    def _tokens(self, coll: Collection, data: dict[str, Any]) -> list[tuple[str, str]]:
        out = []
        index_key = (
            self.keys.key(coll.index_key_id, expected_scope=_scope(coll.name)) if coll.index_key_id else None
        )
        for field in coll.indexed_fields:
            if field not in data:
                continue
            value = data[field]
            try:
                token = blind_token(index_key, coll.name, field, value) if index_key else plain_token(value)
            except ValueError as exc:
                raise ValidationFailed(f"indexed field {field}: {exc}") from exc
            out.append((field, token))
        return out

    def _storage_values(
        self, coll: Collection, record_id: str, data: dict[str, Any], marking: Marking, version: int
    ) -> dict[str, Any]:
        if coll.encrypted:
            key_id, sealed = self.sealer.seal_json(
                _scope(coll.name), _aad(coll.name, record_id, marking, version), data
            )
            return {"data_plain": None, "data_sealed": sealed, "key_id": key_id}
        return {"data_plain": data, "data_sealed": None, "key_id": None}

    def _row(self, coll: str, record_id: str) -> Any:
        with self.db.engine.connect() as conn:
            row = conn.execute(
                select(schema.records).where(
                    schema.records.c.id == record_id,
                    schema.records.c.collection == coll,
                    schema.records.c.deleted_at.is_(None),
                )
            ).first()
        if row is None:
            raise NotFound("record not found")
        return row

    def _view(
        self, coll: Collection, row: Any, *, include_data: bool, reason: str | None = None
    ) -> RecordView:
        marking = Marking.parse(row.marking)
        data = None
        if include_data:
            if row.data_sealed is not None:
                data = self.sealer.open_json(
                    _scope(coll.name),
                    row.key_id,
                    _aad(coll.name, row.id, marking, row.version),
                    bytes(row.data_sealed),
                )
            else:
                data = row.data_plain
        return RecordView(
            id=row.id,
            collection=coll.name,
            marking=marking,
            version=row.version,
            data=data,
            content_withheld=not include_data,
            created_by=row.created_by,
            created_at=row.created_at,
            updated_by=row.updated_by,
            updated_at=row.updated_at,
            withheld_reason=reason,
        )

    def _content_decision(self, ctx: Ctx, marking: Marking) -> tuple[bool, str | None]:
        d = self.guard.peek(ctx, Action.RECORD_READ_CONTENT, marking)
        return (d.allowed, None if d.allowed else d.reason)

    # ---- records ------------------------------------------------------------------------
    def create_record(
        self,
        ctx: Ctx,
        collection: str,
        data: dict[str, Any],
        *,
        marking: Marking | None = None,
        idempotency_key: str | None = None,
    ) -> RecordView:
        coll = self._collection(collection)
        m = self._record_marking(coll, marking)
        self.guard.check(
            ctx,
            Action.RECORD_CREATE,
            resource_type="record",
            resource_id=None,
            marking=m,
            audit_allow=False,
            concealable=False,
        )
        doc = self._validate(coll, data)
        req_hash = _request_hash(doc, m)
        if idempotency_key:
            existing = self._idempotent(ctx, idempotency_key, req_hash)
            if existing:
                return self.get_record(ctx, collection, existing)

        record_id = new_id("rec")
        now = utcnow()
        values = self._storage_values(coll, record_id, doc, m, 1)
        tokens = self._tokens(coll, doc)
        try:
            with self.db.engine.begin() as conn:
                conn.execute(
                    insert(schema.records).values(
                        id=record_id,
                        collection=coll.name,
                        marking=m.banner,
                        version=1,
                        created_by=ctx.principal.subject,
                        created_at=now,
                        updated_by=ctx.principal.subject,
                        updated_at=now,
                        **values,
                    )
                )
                for field, token in tokens:
                    conn.execute(
                        insert(schema.record_index).values(
                            collection=coll.name, field=field, token=token, record_id=record_id
                        )
                    )
                if idempotency_key:
                    conn.execute(
                        insert(schema.idempotency_keys).values(
                            principal=ctx.principal.subject,
                            key=idempotency_key,
                            resource_type="record",
                            resource_id=record_id,
                            request_hash=req_hash,
                            created_at=now,
                        )
                    )
        except IntegrityError:
            if idempotency_key:
                existing = self._idempotent(ctx, idempotency_key, req_hash)
                if existing:
                    return self.get_record(ctx, collection, existing)
            raise
        self.guard.note(
            ctx,
            Action.RECORD_CREATE,
            resource_type="record",
            resource_id=record_id,
            decision="allow",
            reason="record created",
            marking=m,
            details={"collection": coll.name},
        )
        allowed, reason = self._content_decision(ctx, m)
        return self._view(coll, self._row(coll.name, record_id), include_data=allowed, reason=reason)

    def _idempotent(self, ctx: Ctx, key: str, req_hash: str) -> str | None:
        with self.db.engine.connect() as conn:
            row = conn.execute(
                select(schema.idempotency_keys).where(
                    schema.idempotency_keys.c.principal == ctx.principal.subject,
                    schema.idempotency_keys.c.resource_type == "record",
                    schema.idempotency_keys.c.key == key,
                )
            ).first()
        if row is None:
            return None
        if row.request_hash != req_hash:
            raise Conflict("idempotency key was already used with a different request")
        return str(row.resource_id)

    def get_record(self, ctx: Ctx, collection: str, record_id: str) -> RecordView:
        coll = self._collection(collection)
        row = self._row(coll.name, record_id)
        marking = Marking.parse(row.marking)
        self.guard.check(
            ctx,
            Action.RECORD_READ,
            resource_type="record",
            resource_id=record_id,
            marking=marking,
            audit_allow=False,
        )
        content = self.guard.check(
            ctx, Action.RECORD_READ_CONTENT, resource_type="record", resource_id=record_id, marking=marking
        )
        return self._view(
            coll, row, include_data=content.allowed, reason=None if content.allowed else content.reason
        )

    def update_record(
        self,
        ctx: Ctx,
        collection: str,
        record_id: str,
        data: dict[str, Any],
        *,
        expected_version: int,
        marking: Marking | None = None,
    ) -> RecordView:
        coll = self._collection(collection)
        row = self._row(coll.name, record_id)
        current = Marking.parse(row.marking)
        self.guard.check(
            ctx, Action.RECORD_UPDATE, resource_type="record", resource_id=record_id, marking=current
        )
        new_marking = self._record_marking(coll, marking or current)
        if not new_marking.dominates(current):
            raise ValidationFailed(
                "lowering a record's marking (decontrol) is not supported through this API"
            )
        if new_marking != current:
            self.guard.check(
                ctx,
                Action.RECORD_UPDATE,
                resource_type="record",
                resource_id=record_id,
                marking=new_marking,
                concealable=False,
            )
        if row.version != expected_version:
            raise PreconditionFailed(f"record is at version {row.version}, not {expected_version}")
        doc = self._validate(coll, data)
        version = expected_version + 1
        values = self._storage_values(coll, record_id, doc, new_marking, version)
        tokens = self._tokens(coll, doc)
        now = utcnow()
        with self.db.engine.begin() as conn:
            result = conn.execute(
                update(schema.records)
                .where(schema.records.c.id == record_id, schema.records.c.version == expected_version)
                .values(
                    marking=new_marking.banner,
                    version=version,
                    updated_by=ctx.principal.subject,
                    updated_at=now,
                    **values,
                )
            )
            if result.rowcount != 1:
                raise PreconditionFailed("record was modified concurrently")
            conn.execute(delete(schema.record_index).where(schema.record_index.c.record_id == record_id))
            for field, token in tokens:
                conn.execute(
                    insert(schema.record_index).values(
                        collection=coll.name, field=field, token=token, record_id=record_id
                    )
                )
        allowed, reason = self._content_decision(ctx, new_marking)
        return self._view(coll, self._row(coll.name, record_id), include_data=allowed, reason=reason)

    def delete_record(
        self,
        ctx: Ctx,
        collection: str,
        record_id: str,
        *,
        expected_version: int | None = None,
        purge: bool = False,
    ) -> None:
        coll = self._collection(collection)
        row = self._row(coll.name, record_id)
        marking = Marking.parse(row.marking)
        self.guard.check(
            ctx,
            Action.RECORD_DELETE,
            resource_type="record",
            resource_id=record_id,
            marking=marking,
            details={"purge": purge},
        )
        if expected_version is not None and row.version != expected_version:
            raise PreconditionFailed(f"record is at version {row.version}, not {expected_version}")
        with self.db.engine.begin() as conn:
            conn.execute(delete(schema.record_index).where(schema.record_index.c.record_id == record_id))
            if purge:
                conn.execute(delete(schema.records).where(schema.records.c.id == record_id))
            else:
                conn.execute(
                    update(schema.records).where(schema.records.c.id == record_id).values(deleted_at=utcnow())
                )

    def query(
        self,
        ctx: Ctx,
        collection: str,
        *,
        filters: dict[str, Any] | None = None,
        limit: int | None = None,
        cursor: str | None = None,
    ) -> tuple[list[RecordView], str | None]:
        coll = self._collection(collection)
        self.guard.check(
            ctx,
            Action.RECORD_QUERY,
            resource_type="collection",
            resource_id=coll.name,
            marking=coll.marking,
            audit_allow=False,
        )
        filters = filters or {}
        unknown = [f for f in filters if f not in coll.indexed_fields]
        if unknown:
            raise ValidationFailed(
                f"can only filter on indexed fields {list(coll.indexed_fields)}; got {unknown}"
            )
        n = clamp_limit(limit, default=20)
        stmt = select(schema.records).where(
            schema.records.c.collection == coll.name, schema.records.c.deleted_at.is_(None)
        )
        for field, value in filters.items():
            try:
                token = self._tokens(coll, {field: value})[0][1]
            except IndexError:  # pragma: no cover - field always present here
                continue
            stmt = stmt.where(
                schema.records.c.id.in_(
                    select(schema.record_index.c.record_id).where(
                        schema.record_index.c.collection == coll.name,
                        schema.record_index.c.field == field,
                        schema.record_index.c.token == token,
                    )
                )
            )
        cond = before_cursor(schema.records.c.created_at, schema.records.c.id, cursor)
        if cond is not None:
            stmt = stmt.where(cond)
        stmt = stmt.order_by(schema.records.c.created_at.desc(), schema.records.c.id.desc()).limit(n + 1)
        with self.db.engine.connect() as conn:
            rows = conn.execute(stmt).all()
        more = len(rows) > n
        rows = rows[:n]
        views = []
        withheld = 0
        for r in rows:
            m = Marking.parse(r.marking)
            if not self.guard.peek(ctx, Action.RECORD_READ, m).allowed:
                continue
            allowed, reason = self._content_decision(ctx, m)
            withheld += 0 if allowed else 1
            views.append(self._view(coll, r, include_data=allowed, reason=reason))
        self.guard.note(
            ctx,
            Action.RECORD_QUERY,
            resource_type="collection",
            resource_id=coll.name,
            decision="allow",
            reason="queried records",
            marking=coll.marking,
            details={
                "filters": sorted(filters),
                "returned": len(views),
                "withheld": withheld,
                "scanned": len(rows),
            },
        )
        next_cursor = encode_cursor(rows[-1].created_at, rows[-1].id) if more and rows else None
        return views, next_cursor
