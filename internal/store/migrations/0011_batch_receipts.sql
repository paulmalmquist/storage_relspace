SET LOCAL ROLE strongbox_owner;
CREATE INDEX ix_receipts_batch_results ON operation_receipts USING gin(result jsonb_path_ops)
    WHERE resource_type='record_batch';
CREATE OR REPLACE FUNCTION sb_revision_pinned(p_app text,p_id text,p_version integer) RETURNS boolean
LANGUAGE sql STABLE SECURITY DEFINER AS $$
    SELECT p_app=sb_ctx_app() AND sb_ctx_admitted() AND EXISTS(
        SELECT 1 FROM operation_receipts o WHERE o.app=p_app AND o.expires_at>now() AND (
          (o.resource_type='record' AND o.resource_id=p_id AND o.resource_version=p_version)
          OR (o.resource_type='record_batch' AND o.result @> jsonb_build_object('operations',
              jsonb_build_array(jsonb_build_object('id',p_id,'version',p_version))))))
$$;
DO $$ BEGIN
    EXECUTE format('ALTER FUNCTION sb_revision_pinned(text,text,integer) SET search_path = %I, pg_catalog, pg_temp',current_schema());
END $$;
REVOKE ALL ON FUNCTION sb_revision_pinned(text,text,integer) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION sb_revision_pinned(text,text,integer) TO strongbox_runtime;
