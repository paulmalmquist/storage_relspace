-- Versioned collection contracts.
--
-- A collection's contract (JSON Schema, indexed fields, unique fields) has numbered versions. A
-- change that provably accepts every existing record takes effect at once. Any other change is
-- staged as pending_version and a migration job (run by the worker in bounded, resumable batches)
-- applies declared defaults, validates every live record, and backfills index and uniqueness
-- tokens; only then does the collection switch. While a change is pending, writers validate
-- against both contracts. Nothing is rewritten at startup.
--
-- Uniqueness is enforced on blind-index tokens. A unique violation is visible to any writer
-- regardless of row-level security (that is what uniqueness means), so the API reports only that
-- the value is taken, never which record holds it.

SET LOCAL ROLE strongbox_owner;

ALTER TABLE collections ADD COLUMN unique_fields jsonb NOT NULL DEFAULT '[]';
ALTER TABLE collections ADD COLUMN pending_version integer;

CREATE TABLE collection_versions (
    app            text NOT NULL,
    collection     text NOT NULL,
    version        integer NOT NULL CHECK (version >= 1),
    json_schema    jsonb NOT NULL,
    indexed_fields jsonb NOT NULL,
    unique_fields  jsonb NOT NULL,
    created_by     text NOT NULL,
    created_at     timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (app, collection, version),
    FOREIGN KEY (app, collection) REFERENCES collections (app, name) ON DELETE CASCADE DEFERRABLE
);

INSERT INTO collection_versions (app, collection, version, json_schema, indexed_fields, unique_fields, created_by, created_at)
SELECT app, name, version, json_schema, indexed_fields, '[]', created_by, created_at FROM collections;

ALTER TABLE records ADD COLUMN schema_version integer; -- NULL: written before contracts were versioned

CREATE TABLE record_unique (
    app        text NOT NULL,
    collection text NOT NULL,
    field      text NOT NULL,
    token      text NOT NULL,
    record_id  text NOT NULL,
    PRIMARY KEY (app, collection, field, token),
    FOREIGN KEY (app, record_id) REFERENCES records (app, id) ON DELETE CASCADE DEFERRABLE
);
CREATE INDEX ix_record_unique_record ON record_unique (app, record_id);

CREATE TABLE collection_migrations (
    app          text NOT NULL,
    id           text NOT NULL,
    collection   text NOT NULL,
    from_version integer NOT NULL,
    to_version   integer NOT NULL,
    defaults     jsonb NOT NULL DEFAULT '{}',
    state        text NOT NULL DEFAULT 'running' CHECK (state IN ('running', 'succeeded', 'failed', 'cancelled')),
    cursor       text NOT NULL DEFAULT '',
    processed    bigint NOT NULL DEFAULT 0,
    rewritten    bigint NOT NULL DEFAULT 0,
    failures     jsonb NOT NULL DEFAULT '[]',   -- [{record_id, reason}] (at most 100), never content
    created_by   text NOT NULL,
    created_at   timestamptz NOT NULL DEFAULT now(),
    updated_at   timestamptz NOT NULL DEFAULT now(),
    finished_at  timestamptz,
    PRIMARY KEY (app, id),
    FOREIGN KEY (app, collection) REFERENCES collections (app, name) ON DELETE CASCADE DEFERRABLE
);
CREATE UNIQUE INDEX ux_collection_migrations_running ON collection_migrations (app, collection) WHERE state = 'running';
CREATE INDEX ix_collection_migrations_running ON collection_migrations (app) WHERE state = 'running';

ALTER TABLE record_revisions DROP CONSTRAINT record_revisions_op_check;
ALTER TABLE record_revisions ADD CONSTRAINT record_revisions_op_check
    CHECK (op IN ('create', 'update', 'delete', 'restore', 'migrate')) NOT VALID;

-- Policies and privileges ----------------------------------------------------------------------

DO $$
DECLARE t text;
BEGIN
    FOREACH t IN ARRAY ARRAY['collection_versions', 'record_unique', 'collection_migrations'] LOOP
        EXECUTE format('ALTER TABLE %I ENABLE ROW LEVEL SECURITY', t);
        EXECUTE format('ALTER TABLE %I FORCE ROW LEVEL SECURITY', t);
        EXECUTE format('CREATE POLICY maintenance ON %I TO strongbox_owner USING (true) WITH CHECK (true)', t);
        EXECUTE format('CREATE POLICY app_boundary ON %I AS RESTRICTIVE TO strongbox_runtime
            USING (app = (SELECT sb_ctx_app()) AND (SELECT sb_ctx_admitted()))
            WITH CHECK (app = (SELECT sb_ctx_app()) AND (SELECT sb_ctx_admitted()))', t);
        EXECUTE format('REVOKE ALL ON %I FROM PUBLIC', t);
    END LOOP;
END $$;

-- Contracts are readable by everyone admitted; changes need the editor or admin role (as defining
-- a collection does).
CREATE POLICY read ON collection_versions FOR SELECT TO strongbox_runtime USING (true);
CREATE POLICY define ON collection_versions FOR INSERT TO strongbox_runtime
    WITH CHECK ((SELECT sb_ctx_mode()) = 'worker' OR (SELECT sb_ctx_app_role()) IN ('editor', 'admin'));
GRANT SELECT, INSERT ON collection_versions TO strongbox_runtime;

CREATE POLICY read ON collection_migrations FOR SELECT TO strongbox_runtime USING (true);
CREATE POLICY start ON collection_migrations FOR INSERT TO strongbox_runtime
    WITH CHECK ((SELECT sb_ctx_app_role()) IN ('editor', 'admin'));
CREATE POLICY progress ON collection_migrations FOR UPDATE TO strongbox_runtime
    USING ((SELECT sb_ctx_mode()) = 'worker' OR (SELECT sb_ctx_app_role()) IN ('editor', 'admin'))
    WITH CHECK ((SELECT sb_ctx_mode()) = 'worker' OR (SELECT sb_ctx_app_role()) IN ('editor', 'admin'));
GRANT SELECT, INSERT ON collection_migrations TO strongbox_runtime;
GRANT UPDATE (state, cursor, processed, rewritten, failures, updated_at, finished_at) ON collection_migrations TO strongbox_runtime;

-- Uniqueness rows follow their record, like index rows.
CREATE POLICY follows_record ON record_unique FOR ALL TO strongbox_runtime
    USING (EXISTS (SELECT 1 FROM records r WHERE r.app = record_unique.app AND r.id = record_unique.record_id))
    WITH CHECK (EXISTS (SELECT 1 FROM records r WHERE r.app = record_unique.app AND r.id = record_unique.record_id));
GRANT SELECT, INSERT, DELETE ON record_unique TO strongbox_runtime;

GRANT UPDATE (unique_fields, pending_version, index_key_id) ON collections TO strongbox_runtime;
GRANT UPDATE (schema_version) ON records TO strongbox_runtime;
