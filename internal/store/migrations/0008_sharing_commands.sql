SET LOCAL ROLE strongbox_owner;

-- A scoped definer avoids a policy cycle: grant reads must not recursively run
-- resource -> grants -> resource policies. It returns only the caller's share bit.
CREATE FUNCTION sb_can_share_id(p_kind text,p_id text) RETURNS boolean
LANGUAGE plpgsql STABLE SECURITY DEFINER AS $$
DECLARE r record;
BEGIN
    IF sb_ctx_mode()<>'app' OR NOT sb_ctx_admitted() THEN RETURN false; END IF;
    IF p_kind='record' THEN
        SELECT owner,visibility,team_id INTO r FROM records WHERE app=sb_ctx_app() AND id=p_id AND deleted_at IS NULL;
    ELSIF p_kind='blob' THEN
        SELECT owner,visibility,team_id INTO r FROM blobs WHERE app=sb_ctx_app() AND id=p_id AND state='active';
    ELSE RETURN false;
    END IF;
    IF NOT FOUND THEN RETURN false; END IF;
    RETURN sb_can_share(p_kind,p_id,r.owner,r.visibility,r.team_id);
END $$;

-- Sharing is deliberately separate from the general content UPDATE privilege.
-- This function can write exactly visibility/team_id, after checking the OLD row.
CREATE FUNCTION sb_set_visibility(p_kind text,p_id text,p_visibility text,p_team text) RETURNS boolean
LANGUAGE plpgsql SECURITY DEFINER AS $$
BEGIN
    IF sb_ctx_mode()<>'app' OR NOT sb_ctx_admitted() THEN
        RAISE EXCEPTION 'strongbox: app context required' USING ERRCODE='42501';
    END IF;
    IF NOT sb_can_share_id(p_kind,p_id) THEN RETURN false; END IF;
    IF p_kind='record' THEN
        PERFORM 1 FROM records WHERE app=sb_ctx_app() AND id=p_id FOR UPDATE;
    ELSIF p_kind='blob' THEN
        PERFORM 1 FROM blobs WHERE app=sb_ctx_app() AND id=p_id FOR UPDATE;
    ELSE RETURN false;
    END IF;
    IF NOT sb_can_share_id(p_kind,p_id) THEN RETURN false; END IF;
    IF p_kind='record' THEN
        UPDATE records SET visibility=p_visibility,team_id=p_team WHERE app=sb_ctx_app() AND id=p_id AND deleted_at IS NULL;
    ELSE
        UPDATE blobs SET visibility=p_visibility,team_id=p_team WHERE app=sb_ctx_app() AND id=p_id AND state='active';
    END IF;
    RETURN FOUND;
END $$;
DO $$ BEGIN
    EXECUTE format('ALTER FUNCTION sb_can_share_id(text,text) SET search_path = %I, pg_catalog, pg_temp',current_schema());
    EXECUTE format('ALTER FUNCTION sb_set_visibility(text,text,text,text) SET search_path = %I, pg_catalog, pg_temp',current_schema());
END $$;
REVOKE ALL ON FUNCTION sb_can_share_id(text,text),sb_set_visibility(text,text,text,text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION sb_can_share_id(text,text),sb_set_visibility(text,text,text,text) TO strongbox_runtime;

DROP POLICY read ON resource_grants;
CREATE POLICY read ON resource_grants FOR SELECT TO strongbox_runtime USING (
    subject=(SELECT sb_ctx_subject()) OR team_id IN (SELECT t FROM sb_ctx_teams('viewer') t)
    OR granted_by=(SELECT sb_ctx_subject()) OR resource_owner=(SELECT sb_ctx_subject())
    OR (SELECT sb_ctx_app_role())='admin'
    OR sb_can_share_id(CASE WHEN record_id IS NOT NULL THEN 'record' ELSE 'blob' END,coalesce(record_id,blob_id)));
CREATE POLICY changes ON resource_grants FOR UPDATE TO strongbox_runtime USING (
    sb_can_share_id(CASE WHEN record_id IS NOT NULL THEN 'record' ELSE 'blob' END,coalesce(record_id,blob_id)))
WITH CHECK (
    sb_can_share_id(CASE WHEN record_id IS NOT NULL THEN 'record' ELSE 'blob' END,coalesce(record_id,blob_id))
    AND (NOT can_share OR
        EXISTS(SELECT 1 FROM records r WHERE r.app=resource_grants.app AND r.id=record_id AND sb_can_manage(r.owner,r.visibility,r.team_id))
        OR EXISTS(SELECT 1 FROM blobs b WHERE b.app=resource_grants.app AND b.id=blob_id AND sb_can_manage(b.owner,b.visibility,b.team_id))));
