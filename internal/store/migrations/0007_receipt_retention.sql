SET LOCAL ROLE strongbox_owner;

-- Old installations may have raced singleton creation. Keep their wrapped keys
-- readable for existing tokens/receipts; select one active key for future work.
WITH ranked AS (
    SELECT id, row_number() OVER (PARTITION BY app, scope, purpose ORDER BY created_at DESC, id DESC) AS n
    FROM data_keys WHERE purpose='receipt' AND retired_at IS NULL
)
UPDATE data_keys SET retired_at=now() WHERE id IN (SELECT id FROM ranked WHERE n>1);
-- Blind-index tokens cannot be repaired without decrypting/reindexing their rows.
-- Never silently retire a competing index key and make its tokens unreachable.
DO $$ BEGIN
    IF EXISTS(SELECT 1 FROM data_keys WHERE purpose='index' AND retired_at IS NULL
        GROUP BY app,scope HAVING count(*)>1) THEN
        RAISE EXCEPTION 'multiple active blind-index keys: decrypt and rebuild tokens under one key before migration 7' USING ERRCODE='23505';
    END IF;
END $$;
CREATE UNIQUE INDEX ux_data_keys_singleton ON data_keys(app,scope,purpose)
    WHERE purpose IN ('index','receipt') AND retired_at IS NULL;
CREATE INDEX ix_receipts_revision ON operation_receipts(app,resource_id,resource_version,expires_at)
    WHERE resource_type='record';

-- Pinning must see receipts belonging to every actor, not only the next writer.
-- The definer returns one scoped retention bit, never receipt identity or content.
CREATE FUNCTION sb_revision_pinned(p_app text,p_id text,p_version integer) RETURNS boolean
LANGUAGE sql STABLE SECURITY DEFINER AS $$
    SELECT p_app=sb_ctx_app() AND sb_ctx_admitted() AND EXISTS (
        SELECT 1 FROM operation_receipts o WHERE o.app=p_app AND o.resource_type='record'
          AND o.resource_id=p_id AND o.resource_version=p_version AND o.expires_at>now())
$$;
DO $$ BEGIN
    EXECUTE format('ALTER FUNCTION sb_revision_pinned(text,text,integer) SET search_path = %I, pg_catalog, pg_temp',current_schema());
END $$;
REVOKE ALL ON FUNCTION sb_revision_pinned(text,text,integer) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION sb_revision_pinned(text,text,integer) TO strongbox_runtime;
DROP POLICY prune ON record_revisions;
CREATE POLICY prune ON record_revisions FOR DELETE TO strongbox_runtime USING (
    NOT sb_revision_pinned(app,record_id,version) AND (
    (SELECT sb_ctx_mode())='worker' OR EXISTS (
        SELECT 1 FROM records r JOIN collections c ON c.app=r.app AND c.name=r.collection
        WHERE r.app=record_revisions.app AND r.id=record_revisions.record_id
          AND record_revisions.version<=r.version-c.history_limit)));
