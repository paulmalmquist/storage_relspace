"""Relational schema (SQLAlchemy Core). Portable across Postgres and SQLite.

CUI never lands here in plaintext: record documents of encrypted collections, blob filenames and
blob metadata are stored sealed; indexes on encrypted collections hold HMAC blind-index tokens.
Cloud SQL CMEK adds a second, storage-level layer underneath.
"""

from __future__ import annotations

from sqlalchemy import (
    JSON,
    BigInteger,
    Boolean,
    Column,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    LargeBinary,
    MetaData,
    PrimaryKeyConstraint,
    String,
    Table,
)

metadata = MetaData(
    naming_convention={
        "ix": "ix_%(column_0_label)s",
        "uq": "uq_%(table_name)s_%(column_0_name)s",
        "fk": "fk_%(table_name)s_%(column_0_name)s_%(referred_table_name)s",
        "pk": "pk_%(table_name)s",
    }
)

schema_info = Table(
    "schema_info",
    metadata,
    Column("key", String(64), primary_key=True),
    Column("value", String(255), nullable=False),
)

principals = Table(
    "principals",
    metadata,
    Column("subject", String(255), primary_key=True),
    Column("kind", String(16), nullable=False),
    Column("display_name", String(255)),
    Column("scopes", JSON, nullable=False),
    Column("us_person", Boolean, nullable=False, default=False),
    Column("cui_access", Boolean, nullable=False, default=False),
    Column("cui_categories", JSON, nullable=False),
    Column("dissemination", JSON, nullable=False),
    Column("llm_boundary_authorized", Boolean, nullable=False, default=False),
    Column("disabled", Boolean, nullable=False, default=False),
    Column("created_at", DateTime(timezone=True), nullable=False),
    Column("updated_at", DateTime(timezone=True), nullable=False),
)

data_keys = Table(
    "data_keys",
    metadata,
    Column("id", String(40), primary_key=True),
    Column("scope", String(255), nullable=False),
    Column("purpose", String(16), nullable=False),
    Column("kek_id", String(512), nullable=False),
    Column("wrapped_key", LargeBinary, nullable=False),
    Column("created_at", DateTime(timezone=True), nullable=False),
    Column("retired_at", DateTime(timezone=True)),
    Index("ix_data_keys_scope_purpose", "scope", "purpose", "created_at"),
)

blobs = Table(
    "blobs",
    metadata,
    Column("id", String(40), primary_key=True),
    Column("state", String(16), nullable=False),  # pending | active | deleted | shredded
    Column("marking", String(255), nullable=False),
    Column("content_type", String(255), nullable=False),
    Column("size_bytes", BigInteger),
    Column("chunk_size", Integer, nullable=False),
    Column("kek_id", String(512), nullable=False),
    Column("wrapped_dek", LargeBinary),  # NULL after crypto-shred
    Column("meta_key_id", String(40), ForeignKey("data_keys.id"), nullable=False),
    Column("sealed_meta", LargeBinary, nullable=False),
    Column("ciphertext_sha256", String(64)),
    Column("storage_key", String(255), nullable=False),
    Column("created_by", String(255), nullable=False),
    Column("created_at", DateTime(timezone=True), nullable=False),
    Column("deleted_at", DateTime(timezone=True)),
    Column("shredded_at", DateTime(timezone=True)),
    Index("ix_blobs_state_created", "state", "created_at", "id"),
)

collections = Table(
    "collections",
    metadata,
    Column("name", String(64), primary_key=True),
    Column("marking", String(255), nullable=False),
    Column("encrypted", Boolean, nullable=False),
    Column("indexed_fields", JSON, nullable=False),
    Column("json_schema", JSON, nullable=False),
    Column("index_key_id", String(40), ForeignKey("data_keys.id")),
    Column("version", Integer, nullable=False),
    Column("created_by", String(255), nullable=False),
    Column("created_at", DateTime(timezone=True), nullable=False),
    Column("updated_at", DateTime(timezone=True), nullable=False),
)

records = Table(
    "records",
    metadata,
    Column("id", String(40), primary_key=True),
    Column("collection", String(64), ForeignKey("collections.name"), nullable=False),
    Column("marking", String(255), nullable=False),
    Column("data_plain", JSON(none_as_null=True)),  # SQL NULL, not JSON null, when sealed
    Column("data_sealed", LargeBinary),
    Column("key_id", String(40), ForeignKey("data_keys.id")),
    Column("version", Integer, nullable=False),
    Column("created_by", String(255), nullable=False),
    Column("created_at", DateTime(timezone=True), nullable=False),
    Column("updated_by", String(255), nullable=False),
    Column("updated_at", DateTime(timezone=True), nullable=False),
    Column("deleted_at", DateTime(timezone=True)),
    Index("ix_records_collection_created", "collection", "created_at", "id"),
)

record_index = Table(
    "record_index",
    metadata,
    Column("collection", String(64), nullable=False),
    Column("field", String(64), nullable=False),
    Column("token", String(128), nullable=False),
    Column("record_id", String(40), ForeignKey("records.id", ondelete="CASCADE"), nullable=False),
    PrimaryKeyConstraint("collection", "field", "token", "record_id"),
    Index("ix_record_index_record", "record_id"),
)

audit_events = Table(
    "audit_events",
    metadata,
    Column("seq", BigInteger, primary_key=True, autoincrement=False),
    Column("ts", String(40), nullable=False),
    Column("request_id", String(64)),
    Column("actor", String(255), nullable=False),
    Column("actor_kind", String(16), nullable=False),
    Column("on_behalf_of", String(255)),
    Column("action", String(64), nullable=False),
    Column("resource_type", String(32), nullable=False),
    Column("resource_id", String(255)),
    Column("marking", String(255)),
    Column("decision", String(8), nullable=False),
    Column("reason", String(512), nullable=False),
    Column("details", JSON, nullable=False),
    Column("prev_hash", String(64), nullable=False),
    Column("hash", String(64), nullable=False),
    Index("ix_audit_events_actor", "actor", "seq"),
    Index("ix_audit_events_resource", "resource_type", "resource_id"),
)

audit_head = Table(
    "audit_head",
    metadata,
    Column("id", Integer, primary_key=True, autoincrement=False),
    Column("seq", BigInteger, nullable=False),
    Column("hash", String(64), nullable=False),
)

idempotency_keys = Table(
    "idempotency_keys",
    metadata,
    Column("principal", String(255), nullable=False),
    Column("key", String(255), nullable=False),
    Column("resource_type", String(32), nullable=False),
    Column("resource_id", String(255), nullable=False),
    Column("request_hash", String(64)),
    Column("created_at", DateTime(timezone=True), nullable=False),
    PrimaryKeyConstraint("principal", "resource_type", "key"),
)
