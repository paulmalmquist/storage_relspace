-- App scoping. Every app-owned row carries app = '<app_id>:<env>', and every relationship between
-- app-owned rows is a composite foreign key that includes app, so a cross-app reference cannot be
-- stored. Rows that existed before this migration move to the '_legacy' scope. No request context
-- can select it, so they stay invisible until an operator assigns them with
-- `strongbox admin legacy-assign` (docs/STORED_FORMATS.md). They keep their creator as owner and
-- private visibility, so nothing becomes shared by default.
--
-- Runs as the migrating login, which must be a member of strongbox_owner (`strongbox db bootstrap`).

ALTER TABLE principals       OWNER TO strongbox_owner;
ALTER TABLE data_keys        OWNER TO strongbox_owner;
ALTER TABLE blobs            OWNER TO strongbox_owner;
ALTER TABLE collections      OWNER TO strongbox_owner;
ALTER TABLE records          OWNER TO strongbox_owner;
ALTER TABLE record_index     OWNER TO strongbox_owner;
ALTER TABLE audit_events     OWNER TO strongbox_owner;
ALTER TABLE audit_head       OWNER TO strongbox_owner;
ALTER TABLE idempotency_keys OWNER TO strongbox_owner;
ALTER TABLE schema_migrations OWNER TO strongbox_owner;
SET LOCAL ROLE strongbox_owner;

-- Apps, membership and teams ------------------------------------------------------------------

CREATE TABLE apps (
    app          text PRIMARY KEY
                 CHECK (app ~ '^[a-z][a-z0-9-]{1,39}:(dev|test|staging|prod)$' OR app = '_legacy'),
    display_name text,
    status       text NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'suspended', 'legacy')),
    created_by   text NOT NULL,
    created_at   timestamptz NOT NULL DEFAULT now()
);
INSERT INTO apps (app, status, created_by) VALUES ('_legacy', 'legacy', 'migration:0002');

-- Humans and services that act in an app as themselves. Role: viewer < member < editor < admin.
CREATE TABLE app_members (
    app        text NOT NULL REFERENCES apps (app),
    subject    text NOT NULL REFERENCES principals (subject),
    role       text NOT NULL CHECK (role IN ('viewer', 'member', 'editor', 'admin')),
    added_by   text NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (app, subject)
);

-- Workloads (an app's backend, an agent gateway) allowed to act for that app's members (X-On-Behalf-Of).
CREATE TABLE app_clients (
    app        text NOT NULL REFERENCES apps (app),
    subject    text NOT NULL REFERENCES principals (subject),
    added_by   text NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (app, subject)
);

CREATE TABLE teams (
    app        text NOT NULL REFERENCES apps (app),
    id         text NOT NULL,
    name       text NOT NULL CHECK (length(name) BETWEEN 1 AND 120),
    created_by text NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (app, id),
    UNIQUE (app, name)
);

CREATE TABLE team_members (
    app        text NOT NULL,
    team_id    text NOT NULL,
    subject    text NOT NULL REFERENCES principals (subject),
    role       text NOT NULL CHECK (role IN ('viewer', 'editor', 'admin')),
    added_by   text NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (app, team_id, subject),
    FOREIGN KEY (app, team_id) REFERENCES teams (app, id) ON DELETE CASCADE
);
CREATE INDEX ix_team_members_subject ON team_members (app, subject, team_id);

-- Data keys ------------------------------------------------------------------------------------

ALTER TABLE data_keys
    ADD COLUMN app text NOT NULL DEFAULT '_legacy' REFERENCES apps (app),
    ADD COLUMN aad_version smallint NOT NULL DEFAULT 1;   -- 1: strongbox/datakey/v1 (no app)
ALTER TABLE data_keys ALTER COLUMN app DROP DEFAULT, ALTER COLUMN aad_version DROP DEFAULT;
ALTER TABLE data_keys ADD CONSTRAINT data_keys_app_id_key UNIQUE (app, id);
ALTER TABLE data_keys DROP CONSTRAINT data_keys_purpose_check;
ALTER TABLE data_keys ADD CONSTRAINT data_keys_purpose_check CHECK (purpose IN ('data', 'index', 'receipt'));
DROP INDEX ix_data_keys_scope;
CREATE INDEX ix_data_keys_scope ON data_keys (app, scope, purpose, created_at DESC);

-- Collections ----------------------------------------------------------------------------------

ALTER TABLE records DROP CONSTRAINT records_collection_fkey;
ALTER TABLE collections
    ADD COLUMN app text NOT NULL DEFAULT '_legacy' REFERENCES apps (app),
    ADD COLUMN token_version smallint NOT NULL DEFAULT 1;  -- 1: blind tokens without app binding
ALTER TABLE collections ALTER COLUMN app DROP DEFAULT, ALTER COLUMN token_version DROP DEFAULT;
ALTER TABLE collections DROP CONSTRAINT collections_pkey;
ALTER TABLE collections ADD PRIMARY KEY (app, name);
ALTER TABLE collections DROP CONSTRAINT collections_index_key_id_fkey;
ALTER TABLE collections ADD CONSTRAINT collections_index_key_fkey FOREIGN KEY (app, index_key_id)
    REFERENCES data_keys (app, id) DEFERRABLE;

-- Records --------------------------------------------------------------------------------------

ALTER TABLE records
    ADD COLUMN app text NOT NULL DEFAULT '_legacy' REFERENCES apps (app),
    ADD COLUMN owner text,
    ADD COLUMN visibility text NOT NULL DEFAULT 'private' CHECK (visibility IN ('private', 'team', 'app')),
    ADD COLUMN team_id text,
    ADD COLUMN aad_version smallint NOT NULL DEFAULT 1;   -- 1: strongbox/record/v1 (no app)
UPDATE records SET owner = created_by;
ALTER TABLE records
    ALTER COLUMN owner SET NOT NULL,
    ALTER COLUMN app DROP DEFAULT,
    ALTER COLUMN visibility DROP DEFAULT,
    ALTER COLUMN aad_version DROP DEFAULT;
ALTER TABLE records ADD CONSTRAINT records_app_id_key UNIQUE (app, id);
ALTER TABLE records ADD CONSTRAINT records_collection_fkey FOREIGN KEY (app, collection)
    REFERENCES collections (app, name) DEFERRABLE;
ALTER TABLE records DROP CONSTRAINT records_key_id_fkey;
ALTER TABLE records ADD CONSTRAINT records_key_fkey FOREIGN KEY (app, key_id)
    REFERENCES data_keys (app, id) DEFERRABLE;
ALTER TABLE records ADD CONSTRAINT records_team_fkey FOREIGN KEY (app, team_id)
    REFERENCES teams (app, id) DEFERRABLE;
ALTER TABLE records ADD CONSTRAINT records_team_visibility CHECK ((visibility = 'team') = (team_id IS NOT NULL));
-- Controlled content is never stored in plaintext. NOT VALID: rows written before this rule are
-- reported and sealed by `strongbox admin legacy-assign` instead of failing the migration.
ALTER TABLE records ADD CONSTRAINT records_plain_only_uncontrolled
    CHECK (data_plain IS NULL OR marking = 'UNCONTROLLED') NOT VALID;
DROP INDEX ix_records_collection_created;
CREATE INDEX ix_records_list ON records (app, collection, created_at DESC, id DESC);
CREATE INDEX ix_records_marking ON records (app, collection, marking);
CREATE INDEX ix_records_owner ON records (app, owner);
CREATE INDEX ix_records_team ON records (app, team_id) WHERE team_id IS NOT NULL;

ALTER TABLE record_index ADD COLUMN app text NOT NULL DEFAULT '_legacy';
ALTER TABLE record_index ALTER COLUMN app DROP DEFAULT;
ALTER TABLE record_index DROP CONSTRAINT record_index_record_id_fkey;
ALTER TABLE record_index DROP CONSTRAINT record_index_pkey;
ALTER TABLE record_index ADD PRIMARY KEY (app, collection, field, token, record_id);
ALTER TABLE record_index ADD CONSTRAINT record_index_record_fkey FOREIGN KEY (app, record_id)
    REFERENCES records (app, id) ON DELETE CASCADE DEFERRABLE;
ALTER TABLE record_index ADD CONSTRAINT record_index_collection_fkey FOREIGN KEY (app, collection)
    REFERENCES collections (app, name) DEFERRABLE;
DROP INDEX ix_record_index_record;
CREATE INDEX ix_record_index_record ON record_index (app, record_id);

-- Blobs ----------------------------------------------------------------------------------------

ALTER TABLE blobs
    ADD COLUMN app text NOT NULL DEFAULT '_legacy' REFERENCES apps (app),
    ADD COLUMN owner text,
    ADD COLUMN visibility text NOT NULL DEFAULT 'private' CHECK (visibility IN ('private', 'team', 'app')),
    ADD COLUMN team_id text,
    ADD COLUMN aad_version smallint NOT NULL DEFAULT 2,   -- 2: strongbox/blob*/v2 (no app)
    ADD COLUMN lease_owner text,
    ADD COLUMN lease_expires timestamptz;
UPDATE blobs SET owner = created_by;
ALTER TABLE blobs
    ALTER COLUMN owner SET NOT NULL,
    ALTER COLUMN app DROP DEFAULT,
    ALTER COLUMN visibility DROP DEFAULT,
    ALTER COLUMN aad_version DROP DEFAULT;
ALTER TABLE blobs ADD CONSTRAINT blobs_app_id_key UNIQUE (app, id);
ALTER TABLE blobs DROP CONSTRAINT blobs_meta_key_id_fkey;
ALTER TABLE blobs ADD CONSTRAINT blobs_meta_key_fkey FOREIGN KEY (app, meta_key_id)
    REFERENCES data_keys (app, id) DEFERRABLE;
ALTER TABLE blobs ADD CONSTRAINT blobs_team_fkey FOREIGN KEY (app, team_id)
    REFERENCES teams (app, id) DEFERRABLE;
ALTER TABLE blobs ADD CONSTRAINT blobs_team_visibility CHECK ((visibility = 'team') = (team_id IS NOT NULL));
-- pending -> active | aborted;  active -> deleted -> purged;  active|deleted -> shredded.
ALTER TABLE blobs DROP CONSTRAINT blobs_state_check;
ALTER TABLE blobs ADD CONSTRAINT blobs_state_check
    CHECK (state IN ('pending', 'active', 'aborted', 'deleted', 'shredded', 'purged'));
DROP INDEX ix_blobs_state_created;
CREATE INDEX ix_blobs_list ON blobs (app, state, created_at DESC, id DESC);
CREATE INDEX ix_blobs_owner ON blobs (app, owner);
CREATE INDEX ix_blobs_team ON blobs (app, team_id) WHERE team_id IS NOT NULL;
CREATE INDEX ix_blobs_pending_lease ON blobs (lease_expires) WHERE state = 'pending';

-- Grants ---------------------------------------------------------------------------------------

-- Explicit viewer/editor grants to a subject or a team. can_share is separate from edit.
CREATE TABLE resource_grants (
    id             text PRIMARY KEY,
    app            text NOT NULL REFERENCES apps (app),
    record_id      text,
    blob_id        text,
    subject        text REFERENCES principals (subject),
    team_id        text,
    role           text NOT NULL CHECK (role IN ('viewer', 'editor')),
    can_share      boolean NOT NULL,
    resource_owner text NOT NULL,
    granted_by     text NOT NULL,
    created_at     timestamptz NOT NULL DEFAULT now(),
    CHECK ((record_id IS NULL) <> (blob_id IS NULL)),
    CHECK ((subject IS NULL) <> (team_id IS NULL)),
    FOREIGN KEY (app, record_id) REFERENCES records (app, id) ON DELETE CASCADE DEFERRABLE,
    FOREIGN KEY (app, blob_id) REFERENCES blobs (app, id) ON DELETE CASCADE DEFERRABLE,
    FOREIGN KEY (app, team_id) REFERENCES teams (app, id) ON DELETE CASCADE DEFERRABLE
);
CREATE UNIQUE INDEX ux_resource_grants ON resource_grants
    (app, (coalesce(record_id, blob_id)), (coalesce(subject, '')), (coalesce(team_id, '')));
CREATE INDEX ix_grants_subject ON resource_grants (app, subject) WHERE subject IS NOT NULL;
CREATE INDEX ix_grants_team ON resource_grants (app, team_id) WHERE team_id IS NOT NULL;
CREATE INDEX ix_grants_record ON resource_grants (app, record_id) WHERE record_id IS NOT NULL;
CREATE INDEX ix_grants_blob ON resource_grants (app, blob_id) WHERE blob_id IS NOT NULL;

-- Audit: one hash chain per (app, stripe) plus the global chain ---------------------------------

-- Pre-existing events stay on the 'global' chain in format 1. Within a chain, seq order equals
-- commit order because the head row is locked until the writing transaction commits.
ALTER TABLE audit_events
    ADD COLUMN chain text NOT NULL DEFAULT 'global',
    ADD COLUMN app text REFERENCES apps (app),
    ADD COLUMN format smallint NOT NULL DEFAULT 1;
ALTER TABLE audit_events ALTER COLUMN chain DROP DEFAULT, ALTER COLUMN format DROP DEFAULT;
ALTER TABLE audit_events DROP CONSTRAINT audit_events_pkey;
ALTER TABLE audit_events ADD PRIMARY KEY (chain, seq);
DROP INDEX ix_audit_events_actor;
DROP INDEX ix_audit_events_resource;
CREATE INDEX ix_audit_events_app ON audit_events (app, chain, seq);
CREATE INDEX ix_audit_events_resource ON audit_events (app, resource_type, resource_id);

CREATE TABLE audit_heads (
    chain text PRIMARY KEY CHECK (chain = 'global' OR chain ~ '^app:[a-z][a-z0-9-]{1,39}:(dev|test|staging|prod):[0-9]{1,2}$'),
    app   text REFERENCES apps (app),
    seq   bigint NOT NULL,
    hash  text NOT NULL,
    CHECK ((chain = 'global') = (app IS NULL))
);
INSERT INTO audit_heads (chain, app, seq, hash) SELECT 'global', NULL, seq, hash FROM audit_head;

-- audit_head (single global head) and idempotency_keys (unscoped receipts) are superseded by
-- audit_heads and operation_receipts. They are kept for the record and get no runtime grants.
COMMENT ON TABLE audit_head IS 'superseded by audit_heads (0002); kept read-only for the record';
COMMENT ON TABLE idempotency_keys IS 'superseded by operation_receipts; unscoped, never replayed';
