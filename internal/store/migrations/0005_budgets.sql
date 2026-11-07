-- Resource budgets.
--
--   * Per-app quotas. Usage is maintained by triggers on records and blobs, so no code path can
--     forget it. Blob usage is one row per app (reservations are exact: the row is locked by the
--     update that checks it). Record usage is sharded eight ways by record ID so concurrent writers
--     to one app do not serialize; a record's increments and decrements always hit its own shard.
--     The record limit is checked against the sum of all shards after this shard is updated, so
--     concurrent writers on other shards can overshoot it by at most seven records.
--   * Multipart uploads: a blob can be stored as parts, each its own object, so one request never
--     has to carry more than the transport allows.
--   * A marking catalog per listing scope, so list and query compute the caller's allowed markings
--     without scanning the table.
--   * Expiry of deleted records (and with them, their history).
--
-- Everything here is additive. New columns are nullable or have constant defaults, so no table is
-- rewritten.

SET LOCAL ROLE strongbox_owner;

-- Quotas ---------------------------------------------------------------------------------------

CREATE TABLE app_quotas (
    app              text PRIMARY KEY REFERENCES apps (app) ON DELETE CASCADE,
    max_blob_bytes   bigint CHECK (max_blob_bytes >= 0),
    max_blobs        bigint CHECK (max_blobs >= 0),
    max_records      bigint CHECK (max_records >= 0),
    max_record_bytes bigint CHECK (max_record_bytes >= 0),
    updated_by       text NOT NULL,
    updated_at       timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE blob_usage (
    app            text PRIMARY KEY REFERENCES apps (app) ON DELETE CASCADE,
    bytes          bigint NOT NULL DEFAULT 0,   -- active blobs (plaintext size)
    blobs          bigint NOT NULL DEFAULT 0,
    reserved_bytes bigint NOT NULL DEFAULT 0,   -- pending uploads
    reservations   bigint NOT NULL DEFAULT 0
);

CREATE TABLE record_usage (
    app     text NOT NULL REFERENCES apps (app) ON DELETE CASCADE,
    shard   smallint NOT NULL CHECK (shard BETWEEN 0 AND 7),
    records bigint NOT NULL DEFAULT 0,          -- live (not deleted) records
    bytes   bigint NOT NULL DEFAULT 0,          -- stored size of their current content
    PRIMARY KEY (app, shard)
);

-- Deterministic across PostgreSQL versions (unlike hashtext), so a shard never changes under a row.
CREATE FUNCTION sb_usage_shard(id text) RETURNS smallint LANGUAGE sql IMMUTABLE PARALLEL SAFE AS $$
    SELECT (get_byte(sha256(convert_to(id, 'UTF8')), 0) % 8)::smallint
$$;

-- Migrations and admin commands (logins in strongbox_owner) are not refused by quotas; usage is
-- still counted.
CREATE FUNCTION sb_enforce_quotas() RETURNS boolean LANGUAGE sql STABLE AS $$
    SELECT NOT pg_has_role(session_user, 'strongbox_owner', 'MEMBER')
$$;

ALTER TABLE records ADD COLUMN size_bytes integer; -- NULL for rows written before this migration

CREATE FUNCTION sb_record_size() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    NEW.size_bytes := coalesce(octet_length(NEW.data_sealed), octet_length(NEW.data_plain::text), 0);
    RETURN NEW;
END $$;

CREATE FUNCTION sb_record_bytes(r records) RETURNS bigint LANGUAGE sql IMMUTABLE AS $$
    SELECT coalesce(r.size_bytes, octet_length(r.data_sealed), octet_length(r.data_plain::text), 0)::bigint
$$;

CREATE FUNCTION sb_record_usage() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER AS $$
DECLARE
    o_live boolean := TG_OP <> 'INSERT' AND OLD.deleted_at IS NULL;
    n_live boolean := TG_OP <> 'DELETE' AND NEW.deleted_at IS NULL;
    v_app text;
    v_id text;
    dc bigint;
    db bigint;
    q app_quotas;
    total_c bigint;
    total_b bigint;
BEGIN
    IF TG_OP = 'UPDATE' AND (OLD.app, OLD.id) IS DISTINCT FROM (NEW.app, NEW.id) THEN
        -- Moved between apps (maintenance only): release from the old app, charge the new one.
        IF o_live THEN
            INSERT INTO record_usage AS u (app, shard, records, bytes)
            VALUES (OLD.app, sb_usage_shard(OLD.id), -1, -sb_record_bytes(OLD))
            ON CONFLICT (app, shard) DO UPDATE SET records = u.records + EXCLUDED.records, bytes = u.bytes + EXCLUDED.bytes;
        END IF;
        IF n_live THEN
            INSERT INTO record_usage AS u (app, shard, records, bytes)
            VALUES (NEW.app, sb_usage_shard(NEW.id), 1, sb_record_bytes(NEW))
            ON CONFLICT (app, shard) DO UPDATE SET records = u.records + EXCLUDED.records, bytes = u.bytes + EXCLUDED.bytes;
        END IF;
        RETURN NULL;
    END IF;
    IF TG_OP = 'DELETE' THEN
        v_app := OLD.app; v_id := OLD.id;
    ELSE
        v_app := NEW.app; v_id := NEW.id;
    END IF;
    dc := (CASE WHEN n_live THEN 1 ELSE 0 END) - (CASE WHEN o_live THEN 1 ELSE 0 END);
    db := (CASE WHEN n_live THEN sb_record_bytes(NEW) ELSE 0 END) - (CASE WHEN o_live THEN sb_record_bytes(OLD) ELSE 0 END);
    IF dc = 0 AND db = 0 THEN
        RETURN NULL;
    END IF;
    INSERT INTO record_usage AS u (app, shard, records, bytes) VALUES (v_app, sb_usage_shard(v_id), dc, db)
    ON CONFLICT (app, shard) DO UPDATE SET records = u.records + EXCLUDED.records, bytes = u.bytes + EXCLUDED.bytes;
    IF (dc > 0 OR db > 0) AND sb_enforce_quotas() THEN
        SELECT * INTO q FROM app_quotas WHERE app = v_app;
        IF FOUND AND (q.max_records IS NOT NULL OR q.max_record_bytes IS NOT NULL) THEN
            SELECT sum(records), sum(bytes) INTO total_c, total_b FROM record_usage WHERE app = v_app;
            IF dc > 0 AND total_c > q.max_records THEN
                RAISE EXCEPTION 'strongbox: record quota exceeded' USING ERRCODE = '53400', DETAIL = 'max_records';
            END IF;
            IF db > 0 AND total_b > q.max_record_bytes THEN
                RAISE EXCEPTION 'strongbox: record storage quota exceeded' USING ERRCODE = '53400', DETAIL = 'max_record_bytes';
            END IF;
        END IF;
    END IF;
    RETURN NULL;
END $$;

-- Multipart uploads ----------------------------------------------------------------------------

ALTER TABLE blobs ADD COLUMN layout text NOT NULL DEFAULT 'single';
ALTER TABLE blobs ADD CONSTRAINT blobs_layout CHECK (layout IN ('single', 'parts')) NOT VALID;
ALTER TABLE blobs ADD COLUMN part_size integer;       -- plaintext bytes per part (parts layout)
ALTER TABLE blobs ADD COLUMN declared_size bigint;    -- total plaintext size promised at session start
ALTER TABLE blobs ADD COLUMN reserved_bytes bigint NOT NULL DEFAULT 0;

CREATE TABLE blob_parts (
    app               text NOT NULL,
    blob_id           text NOT NULL,
    part_number       integer NOT NULL CHECK (part_number >= 1),
    storage_key       text NOT NULL,
    size_bytes        integer NOT NULL,            -- plaintext
    cipher_bytes      integer NOT NULL,
    ciphertext_sha256 text NOT NULL,
    created_at        timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (app, blob_id, part_number),
    FOREIGN KEY (app, blob_id) REFERENCES blobs (app, id) ON DELETE CASCADE DEFERRABLE
);

CREATE FUNCTION sb_blob_usage() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER AS $$
DECLARE
    o_used bigint := 0; o_res bigint := 0; o_n bigint := 0; o_r bigint := 0;
    n_used bigint := 0; n_res bigint := 0; n_n bigint := 0; n_r bigint := 0;
    v_app text;
    q app_quotas;
    u blob_usage;
BEGIN
    IF TG_OP <> 'INSERT' THEN
        IF OLD.state = 'active' THEN o_used := coalesce(OLD.size_bytes, 0); o_n := 1;
        ELSIF OLD.state = 'pending' THEN o_res := OLD.reserved_bytes; o_r := 1; END IF;
    END IF;
    IF TG_OP <> 'DELETE' THEN
        IF NEW.state = 'active' THEN n_used := coalesce(NEW.size_bytes, 0); n_n := 1;
        ELSIF NEW.state = 'pending' THEN n_res := NEW.reserved_bytes; n_r := 1; END IF;
    END IF;
    IF TG_OP = 'UPDATE' AND OLD.app IS DISTINCT FROM NEW.app THEN
        INSERT INTO blob_usage AS b (app, bytes, blobs, reserved_bytes, reservations) VALUES (OLD.app, -o_used, -o_n, -o_res, -o_r)
        ON CONFLICT (app) DO UPDATE SET bytes = b.bytes + EXCLUDED.bytes, blobs = b.blobs + EXCLUDED.blobs,
            reserved_bytes = b.reserved_bytes + EXCLUDED.reserved_bytes, reservations = b.reservations + EXCLUDED.reservations;
        o_used := 0; o_n := 0; o_res := 0; o_r := 0;
    END IF;
    IF n_used = o_used AND n_res = o_res AND n_n = o_n AND n_r = o_r THEN
        RETURN NULL;
    END IF;
    v_app := CASE WHEN TG_OP = 'DELETE' THEN OLD.app ELSE NEW.app END;
    INSERT INTO blob_usage AS b (app, bytes, blobs, reserved_bytes, reservations)
    VALUES (v_app, n_used - o_used, n_n - o_n, n_res - o_res, n_r - o_r)
    ON CONFLICT (app) DO UPDATE SET bytes = b.bytes + EXCLUDED.bytes, blobs = b.blobs + EXCLUDED.blobs,
        reserved_bytes = b.reserved_bytes + EXCLUDED.reserved_bytes, reservations = b.reservations + EXCLUDED.reservations
    RETURNING b.* INTO u;
    IF ((n_used + n_res) > (o_used + o_res) OR (n_n + n_r) > (o_n + o_r)) AND sb_enforce_quotas() THEN
        SELECT * INTO q FROM app_quotas WHERE app = v_app;
        IF FOUND THEN
            IF (n_used + n_res) > (o_used + o_res) AND u.bytes + u.reserved_bytes > q.max_blob_bytes THEN
                RAISE EXCEPTION 'strongbox: blob storage quota exceeded' USING ERRCODE = '53400', DETAIL = 'max_blob_bytes';
            END IF;
            IF (n_n + n_r) > (o_n + o_r) AND u.blobs + u.reservations > q.max_blobs THEN
                RAISE EXCEPTION 'strongbox: blob count quota exceeded' USING ERRCODE = '53400', DETAIL = 'max_blobs';
            END IF;
        END IF;
    END IF;
    RETURN NULL;
END $$;

-- Marking catalog ------------------------------------------------------------------------------
-- Which markings occur in each listing scope ('blobs' or 'collection:<name>'). Entries are never
-- removed; a stale entry only widens the allowed set passed to a query that RLS still filters.

CREATE TABLE marking_catalog (
    app     text NOT NULL REFERENCES apps (app) ON DELETE CASCADE,
    scope   text NOT NULL,
    marking text NOT NULL,
    PRIMARY KEY (app, scope, marking)
);

CREATE FUNCTION sb_catalog_marking() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER AS $$
DECLARE v_scope text := 'blobs';
BEGIN
    IF TG_OP = 'INSERT' OR NEW.marking IS DISTINCT FROM OLD.marking OR NEW.app IS DISTINCT FROM OLD.app THEN
        -- PL/pgSQL resolves every field reference in an expression, so the records-only column
        -- is read in its own branch.
        IF TG_TABLE_NAME = 'records' THEN
            v_scope := 'collection:' || NEW.collection;
        END IF;
        INSERT INTO marking_catalog (app, scope, marking) VALUES (NEW.app, v_scope, NEW.marking) ON CONFLICT DO NOTHING;
    END IF;
    RETURN NULL;
END $$;

-- Deleted-record expiry -------------------------------------------------------------------------

ALTER TABLE collections ADD COLUMN deleted_retention_days integer NOT NULL DEFAULT 30;
ALTER TABLE collections ADD CONSTRAINT collections_deleted_retention
    CHECK (deleted_retention_days BETWEEN 1 AND 3650) NOT VALID;
CREATE INDEX ix_records_deleted ON records (app, deleted_at) WHERE deleted_at IS NOT NULL;

-- Backfill, then triggers ----------------------------------------------------------------------

INSERT INTO record_usage (app, shard, records, bytes)
SELECT app, sb_usage_shard(id), count(*), sum(sb_record_bytes(records))
FROM records WHERE deleted_at IS NULL GROUP BY 1, 2;

INSERT INTO blob_usage (app, bytes, blobs, reserved_bytes, reservations)
SELECT app,
       coalesce(sum(size_bytes) FILTER (WHERE state = 'active'), 0),
       count(*) FILTER (WHERE state = 'active'),
       coalesce(sum(reserved_bytes) FILTER (WHERE state = 'pending'), 0),
       count(*) FILTER (WHERE state = 'pending')
FROM blobs GROUP BY app;

INSERT INTO marking_catalog (app, scope, marking)
SELECT DISTINCT app, 'collection:' || collection, marking FROM records
UNION
SELECT DISTINCT app, 'blobs', marking FROM blobs;

CREATE TRIGGER size BEFORE INSERT OR UPDATE OF data_plain, data_sealed ON records
    FOR EACH ROW EXECUTE FUNCTION sb_record_size();
CREATE TRIGGER usage AFTER INSERT OR UPDATE OR DELETE ON records
    FOR EACH ROW EXECUTE FUNCTION sb_record_usage();
CREATE TRIGGER usage AFTER INSERT OR UPDATE OR DELETE ON blobs
    FOR EACH ROW EXECUTE FUNCTION sb_blob_usage();
CREATE TRIGGER catalog AFTER INSERT OR UPDATE OF marking, app ON records
    FOR EACH ROW EXECUTE FUNCTION sb_catalog_marking();
CREATE TRIGGER catalog AFTER INSERT OR UPDATE OF marking, app ON blobs
    FOR EACH ROW EXECUTE FUNCTION sb_catalog_marking();

-- SECURITY DEFINER functions run as strongbox_owner with a pinned search path.
DO $$
BEGIN
    EXECUTE format('ALTER FUNCTION sb_record_usage() SET search_path = %I, pg_catalog, pg_temp', current_schema());
    EXECUTE format('ALTER FUNCTION sb_blob_usage() SET search_path = %I, pg_catalog, pg_temp', current_schema());
    EXECUTE format('ALTER FUNCTION sb_catalog_marking() SET search_path = %I, pg_catalog, pg_temp', current_schema());
END $$;

-- Policies and privileges ----------------------------------------------------------------------

DO $$
DECLARE t text;
BEGIN
    FOREACH t IN ARRAY ARRAY['app_quotas', 'blob_usage', 'record_usage', 'blob_parts', 'marking_catalog'] LOOP
        EXECUTE format('ALTER TABLE %I ENABLE ROW LEVEL SECURITY', t);
        EXECUTE format('ALTER TABLE %I FORCE ROW LEVEL SECURITY', t);
        EXECUTE format('CREATE POLICY maintenance ON %I TO strongbox_owner USING (true) WITH CHECK (true)', t);
        EXECUTE format('CREATE POLICY app_boundary ON %I AS RESTRICTIVE TO strongbox_runtime
            USING (app = (SELECT sb_ctx_app()) AND (SELECT sb_ctx_admitted()))
            WITH CHECK (app = (SELECT sb_ctx_app()) AND (SELECT sb_ctx_admitted()))', t);
        EXECUTE format('REVOKE ALL ON %I FROM PUBLIC', t);
    END LOOP;
END $$;

-- Quotas, usage and the catalog are readable inside the app and written only by the owner role
-- (admin CLI, definer triggers).
CREATE POLICY read ON app_quotas FOR SELECT TO strongbox_runtime USING (true);
CREATE POLICY read ON blob_usage FOR SELECT TO strongbox_runtime USING (true);
CREATE POLICY read ON record_usage FOR SELECT TO strongbox_runtime USING (true);
CREATE POLICY read ON marking_catalog FOR SELECT TO strongbox_runtime USING (true);
GRANT SELECT ON app_quotas, blob_usage, record_usage, marking_catalog TO strongbox_runtime;

-- Parts follow their blob's visibility; only the uploader writes them, and only while pending.
CREATE POLICY follows_blob ON blob_parts FOR SELECT TO strongbox_runtime
    USING (EXISTS (SELECT 1 FROM blobs b WHERE b.app = blob_parts.app AND b.id = blob_parts.blob_id));
CREATE POLICY upload ON blob_parts FOR INSERT TO strongbox_runtime
    WITH CHECK (EXISTS (SELECT 1 FROM blobs b WHERE b.app = blob_parts.app AND b.id = blob_parts.blob_id
                        AND b.state = 'pending' AND b.owner = (SELECT sb_ctx_subject())));
CREATE POLICY reupload ON blob_parts FOR UPDATE TO strongbox_runtime
    USING (EXISTS (SELECT 1 FROM blobs b WHERE b.app = blob_parts.app AND b.id = blob_parts.blob_id
                   AND b.state = 'pending' AND b.owner = (SELECT sb_ctx_subject())))
    WITH CHECK (EXISTS (SELECT 1 FROM blobs b WHERE b.app = blob_parts.app AND b.id = blob_parts.blob_id
                        AND b.state = 'pending' AND b.owner = (SELECT sb_ctx_subject())));
GRANT SELECT, INSERT ON blob_parts TO strongbox_runtime;
GRANT UPDATE (storage_key, size_bytes, cipher_bytes, ciphertext_sha256, created_at) ON blob_parts TO strongbox_runtime;

GRANT UPDATE (deleted_retention_days) ON collections TO strongbox_runtime;

REVOKE ALL ON FUNCTION sb_usage_shard(text), sb_enforce_quotas(), sb_record_size(), sb_record_bytes(records),
    sb_record_usage(), sb_blob_usage(), sb_catalog_marking() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION sb_usage_shard(text), sb_enforce_quotas(), sb_record_size(), sb_record_bytes(records),
    sb_record_usage(), sb_blob_usage(), sb_catalog_marking() TO strongbox_runtime;

-- History is trimmed when a record is written, so no background scan over all revisions is needed.
-- A writer may delete only revisions that are already past the collection's history limit.
DROP POLICY prune ON record_revisions;
CREATE POLICY prune ON record_revisions FOR DELETE TO strongbox_runtime USING (
    (SELECT sb_ctx_mode()) = 'worker'
    OR EXISTS (SELECT 1 FROM records r JOIN collections c ON c.app = r.app AND c.name = r.collection
               WHERE r.app = record_revisions.app AND r.id = record_revisions.record_id
                 AND record_revisions.version <= r.version - c.history_limit));

-- Finished outbox jobs are removed after a day so the table stays proportional to pending work;
-- dead jobs stay until an operator looks at them.
CREATE INDEX ix_outbox_done ON outbox (updated_at) WHERE status = 'done';
CREATE INDEX ix_outbox_dead ON outbox (id) WHERE status = 'dead';
CREATE POLICY prune ON outbox FOR DELETE TO strongbox_runtime
    USING ((SELECT sb_ctx_mode()) = 'dispatcher' AND status = 'done');
GRANT DELETE ON outbox TO strongbox_runtime;
