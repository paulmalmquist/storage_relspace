SET LOCAL ROLE strongbox_owner;

CREATE OR REPLACE FUNCTION sb_record_usage() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER AS $$
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
    -- A quota reservation precedes every positive shard change. This bounds
    -- concurrent multi-record transactions as well as one-row HTTP mutations.
    IF (dc>0 OR db>0) AND sb_enforce_quotas() THEN
        PERFORM 1 FROM app_quotas WHERE app=v_app
            AND (max_records IS NOT NULL OR max_record_bytes IS NOT NULL) FOR UPDATE;
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

DO $$ BEGIN
    EXECUTE format('ALTER FUNCTION sb_record_usage() SET search_path = %I, pg_catalog, pg_temp',current_schema());
END $$;
