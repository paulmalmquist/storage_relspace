-- Strongbox schema. CUI never lands here in plaintext: record documents of encrypted collections,
-- blob filenames and blob metadata are sealed; indexes on encrypted collections hold HMAC tokens.
-- Cloud SQL CMEK adds a second, storage-level layer underneath.

CREATE TABLE principals (
    subject                 text PRIMARY KEY,
    kind                    text NOT NULL CHECK (kind IN ('user', 'service', 'agent')),
    display_name            text,
    scopes                  jsonb NOT NULL DEFAULT '[]',
    us_person               boolean NOT NULL DEFAULT false,
    cui_access              boolean NOT NULL DEFAULT false,
    cui_categories          jsonb NOT NULL DEFAULT '[]',
    dissemination           jsonb NOT NULL DEFAULT '[]',
    llm_boundary_authorized boolean NOT NULL DEFAULT false,
    disabled                boolean NOT NULL DEFAULT false,
    created_at              timestamptz NOT NULL DEFAULT now(),
    updated_at              timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE data_keys (
    id          text PRIMARY KEY,
    scope       text NOT NULL,
    purpose     text NOT NULL CHECK (purpose IN ('data', 'index')),
    kek_id      text NOT NULL,
    wrapped_key bytea NOT NULL,
    created_at  timestamptz NOT NULL DEFAULT now(),
    retired_at  timestamptz
);
CREATE INDEX ix_data_keys_scope ON data_keys (scope, purpose, created_at DESC);

CREATE TABLE blobs (
    id                text PRIMARY KEY,
    state             text NOT NULL CHECK (state IN ('pending', 'active', 'deleted', 'shredded')),
    marking           text NOT NULL,
    content_type      text NOT NULL,
    size_bytes        bigint,
    chunk_size        integer NOT NULL,
    kek_id            text NOT NULL,
    wrapped_dek       bytea,          -- NULL after crypto-shred
    meta_key_id       text NOT NULL REFERENCES data_keys (id),
    sealed_meta       bytea NOT NULL,
    ciphertext_sha256 text,
    storage_key       text NOT NULL,
    created_by        text NOT NULL,
    created_at        timestamptz NOT NULL DEFAULT now(),
    deleted_at        timestamptz,
    shredded_at       timestamptz
);
CREATE INDEX ix_blobs_state_created ON blobs (state, created_at DESC, id DESC);

CREATE TABLE collections (
    name           text PRIMARY KEY,
    marking        text NOT NULL,
    encrypted      boolean NOT NULL,
    indexed_fields jsonb NOT NULL DEFAULT '[]',
    json_schema    jsonb NOT NULL,
    index_key_id   text REFERENCES data_keys (id),
    version        integer NOT NULL DEFAULT 1,
    created_by     text NOT NULL,
    created_at     timestamptz NOT NULL DEFAULT now(),
    updated_at     timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE records (
    id          text PRIMARY KEY,
    collection  text NOT NULL REFERENCES collections (name),
    marking     text NOT NULL,
    data_plain  jsonb,                -- only for UNCONTROLLED, unencrypted collections
    data_sealed bytea,
    key_id      text REFERENCES data_keys (id),
    version     integer NOT NULL,
    created_by  text NOT NULL,
    created_at  timestamptz NOT NULL DEFAULT now(),
    updated_by  text NOT NULL,
    updated_at  timestamptz NOT NULL DEFAULT now(),
    deleted_at  timestamptz,
    CHECK ((data_plain IS NULL) <> (data_sealed IS NULL))
);
CREATE INDEX ix_records_collection_created ON records (collection, created_at DESC, id DESC);

CREATE TABLE record_index (
    collection text NOT NULL,
    field      text NOT NULL,
    token      text NOT NULL,
    record_id  text NOT NULL REFERENCES records (id) ON DELETE CASCADE,
    PRIMARY KEY (collection, field, token, record_id)
);
CREATE INDEX ix_record_index_record ON record_index (record_id);

CREATE TABLE audit_events (
    seq           bigint PRIMARY KEY,
    ts            text NOT NULL,
    request_id    text,
    actor         text NOT NULL,
    actor_kind    text NOT NULL,
    on_behalf_of  text,
    action        text NOT NULL,
    resource_type text NOT NULL,
    resource_id   text,
    marking       text,
    decision      text NOT NULL,
    reason        text NOT NULL,
    details       jsonb NOT NULL DEFAULT '{}',
    prev_hash     text NOT NULL,
    hash          text NOT NULL
);
CREATE INDEX ix_audit_events_actor ON audit_events (actor, seq);
CREATE INDEX ix_audit_events_resource ON audit_events (resource_type, resource_id);

CREATE TABLE audit_head (
    id   integer PRIMARY KEY CHECK (id = 1),
    seq  bigint NOT NULL,
    hash text NOT NULL
);
INSERT INTO audit_head (id, seq, hash) VALUES (1, 0, repeat('0', 64));

CREATE TABLE idempotency_keys (
    principal     text NOT NULL,
    resource_type text NOT NULL,
    key           text NOT NULL,
    resource_id   text NOT NULL,
    request_hash  text,
    created_at    timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (principal, resource_type, key)
);
