-- Row-level security for app-owned tables.
--
-- Trust boundary: the service sets strongbox.app / subject / actor / mode with set_config(..., true)
-- after authenticating the caller. These settings are not credentials. Any code holding the runtime
-- login could set them. What RLS adds is a second, independent check that each query stays inside
-- one app, inside the caller's membership, and inside the caller's sharing rights. A forgotten
-- WHERE clause, a wrong ID or a cross-app join then fails closed instead of leaking. Apps never
-- receive database credentials.
--
-- Policy shape per table:
--   * one RESTRICTIVE policy: app = current app AND the caller is admitted to it. Restrictive
--     policies are ANDed with everything else, so no sharing policy can widen the app boundary.
--   * PERMISSIVE per-command policies for owner / team / app-wide / grant sharing.
-- Context readers raise 42501 when a setting is missing, empty or malformed, so an unscoped query
-- errors instead of returning rows. Uncorrelated (SELECT fn()) subqueries run once per statement.

SET LOCAL ROLE strongbox_owner;

-- Context readers ------------------------------------------------------------------------------

CREATE FUNCTION sb_ctx_app() RETURNS text LANGUAGE plpgsql STABLE PARALLEL SAFE AS $$
DECLARE v text := current_setting('strongbox.app', true);
BEGIN
    IF v IS NULL OR v !~ '^[a-z][a-z0-9-]{1,39}:(dev|test|staging|prod)$' THEN
        RAISE EXCEPTION 'strongbox: app context is missing or malformed' USING ERRCODE = '42501';
    END IF;
    RETURN v;
END $$;

CREATE FUNCTION sb_ctx_subject() RETURNS text LANGUAGE plpgsql STABLE PARALLEL SAFE AS $$
DECLARE v text := current_setting('strongbox.subject', true);
BEGIN
    IF v IS NULL OR v = '' OR length(v) > 255 OR v ~ '[[:cntrl:]]' THEN
        RAISE EXCEPTION 'strongbox: subject context is missing or malformed' USING ERRCODE = '42501';
    END IF;
    RETURN v;
END $$;

CREATE FUNCTION sb_ctx_actor() RETURNS text LANGUAGE plpgsql STABLE PARALLEL SAFE AS $$
DECLARE v text := current_setting('strongbox.actor', true);
BEGIN
    IF v IS NULL OR v = '' OR length(v) > 255 OR v ~ '[[:cntrl:]]' THEN
        RAISE EXCEPTION 'strongbox: actor context is missing or malformed' USING ERRCODE = '42501';
    END IF;
    RETURN v;
END $$;

-- app: a request for one app. worker: background work for one app (no member checks; still pinned
-- to the app). global: principals and the global audit chain. dispatcher: job/queue bookkeeping.
CREATE FUNCTION sb_ctx_mode() RETURNS text LANGUAGE plpgsql STABLE PARALLEL SAFE AS $$
DECLARE v text := current_setting('strongbox.mode', true);
BEGIN
    IF v IS NULL OR v NOT IN ('app', 'worker', 'global', 'dispatcher') THEN
        RAISE EXCEPTION 'strongbox: mode context is missing or malformed' USING ERRCODE = '42501';
    END IF;
    RETURN v;
END $$;

CREATE FUNCTION sb_ctx_app_role() RETURNS text LANGUAGE sql STABLE AS $$
    SELECT m.role FROM app_members m WHERE m.app = sb_ctx_app() AND m.subject = sb_ctx_subject()
$$;

-- Admission: the app is active, the subject is a member, and a delegating actor is a registered
-- client of this app. Workers are admitted to exactly the app they were started for.
CREATE FUNCTION sb_ctx_admitted() RETURNS boolean LANGUAGE sql STABLE AS $$
    SELECT CASE sb_ctx_mode()
        WHEN 'worker' THEN sb_ctx_app() IS NOT NULL
        WHEN 'app' THEN
            EXISTS (SELECT 1 FROM apps a WHERE a.app = sb_ctx_app() AND a.status = 'active')
            AND EXISTS (SELECT 1 FROM app_members m WHERE m.app = sb_ctx_app() AND m.subject = sb_ctx_subject())
            AND (sb_ctx_actor() = sb_ctx_subject()
                 OR EXISTS (SELECT 1 FROM app_clients c WHERE c.app = sb_ctx_app() AND c.subject = sb_ctx_actor()))
        ELSE false
    END
$$;

-- Teams the subject belongs to with at least min_role (viewer < editor < admin).
CREATE FUNCTION sb_ctx_teams(min_role text) RETURNS SETOF text LANGUAGE sql STABLE AS $$
    SELECT t.team_id FROM team_members t
    WHERE t.app = sb_ctx_app() AND t.subject = sb_ctx_subject()
      AND CASE min_role WHEN 'viewer' THEN true
                        WHEN 'editor' THEN t.role IN ('editor', 'admin')
                        ELSE t.role = 'admin' END
$$;

-- Resource IDs granted to the subject (directly or through a team). need: viewer | editor | share.
CREATE FUNCTION sb_ctx_granted(kind text, need text) RETURNS SETOF text LANGUAGE sql STABLE AS $$
    SELECT coalesce(g.record_id, g.blob_id) FROM resource_grants g
    WHERE g.app = sb_ctx_app()
      AND CASE kind WHEN 'record' THEN g.record_id IS NOT NULL ELSE g.blob_id IS NOT NULL END
      AND CASE need WHEN 'viewer' THEN true WHEN 'editor' THEN g.role = 'editor' ELSE g.can_share END
      AND (g.subject = sb_ctx_subject() OR g.team_id IN (SELECT t FROM sb_ctx_teams('viewer') t))
$$;

-- Manage = delete and change visibility: owner, app admin for app-wide, team admin for team-shared.
CREATE FUNCTION sb_can_manage(p_owner text, p_visibility text, p_team text) RETURNS boolean LANGUAGE sql STABLE AS $$
    SELECT sb_ctx_mode() = 'worker'
        OR p_owner = sb_ctx_subject()
        OR (p_visibility = 'app' AND sb_ctx_app_role() = 'admin')
        OR (p_visibility = 'team' AND p_team IN (SELECT t FROM sb_ctx_teams('admin') t))
$$;

-- Share = grant viewer/editor access: managers plus grantees with can_share.
CREATE FUNCTION sb_can_share(kind text, p_id text, p_owner text, p_visibility text, p_team text) RETURNS boolean
LANGUAGE sql STABLE AS $$
    SELECT sb_can_manage(p_owner, p_visibility, p_team) OR p_id IN (SELECT g FROM sb_ctx_granted(kind, 'share') g)
$$;

-- Sharing (visibility/team) and deletion are separate rights from editing. UPDATE policies only
-- know the new row, so this trigger checks the old row.
CREATE FUNCTION sb_guard_resource_update() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE kind text := CASE TG_TABLE_NAME WHEN 'records' THEN 'record' ELSE 'blob' END;
BEGIN
    -- The maintenance path (owner role, or a superuser that bypasses RLS) is not subject to sharing.
    IF current_user = 'strongbox_owner' OR NOT row_security_active(TG_RELID::regclass) THEN
        RETURN NEW;
    END IF;
    IF sb_ctx_mode() <> 'worker' THEN
        IF (NEW.visibility, NEW.team_id) IS DISTINCT FROM (OLD.visibility, OLD.team_id)
           AND NOT sb_can_share(kind, OLD.id, OLD.owner, OLD.visibility, OLD.team_id) THEN
            RAISE EXCEPTION 'strongbox: changing visibility requires share permission' USING ERRCODE = '42501';
        END IF;
        IF NEW.deleted_at IS DISTINCT FROM OLD.deleted_at
           AND NOT sb_can_manage(OLD.owner, OLD.visibility, OLD.team_id) THEN
            RAISE EXCEPTION 'strongbox: deleting requires manage permission' USING ERRCODE = '42501';
        END IF;
    END IF;
    RETURN NEW;
END $$;
CREATE TRIGGER guard_update BEFORE UPDATE ON records FOR EACH ROW EXECUTE FUNCTION sb_guard_resource_update();
CREATE TRIGGER guard_update BEFORE UPDATE ON blobs FOR EACH ROW EXECUTE FUNCTION sb_guard_resource_update();

-- Policies -------------------------------------------------------------------------------------

DO $$
DECLARE t text;
BEGIN
    FOREACH t IN ARRAY ARRAY['apps', 'app_members', 'app_clients', 'teams', 'team_members', 'data_keys',
                             'collections', 'records', 'record_index', 'blobs', 'resource_grants',
                             'audit_events', 'audit_heads'] LOOP
        EXECUTE format('ALTER TABLE %I ENABLE ROW LEVEL SECURITY', t);
        EXECUTE format('ALTER TABLE %I FORCE ROW LEVEL SECURITY', t);
        -- The owner role is the privileged maintenance path (legacy-assign, ownership transfer,
        -- export). It is not granted to the runtime login.
        EXECUTE format('CREATE POLICY maintenance ON %I TO strongbox_owner USING (true) WITH CHECK (true)', t);
    END LOOP;
    -- The app boundary on every table that holds app data.
    FOREACH t IN ARRAY ARRAY['teams', 'team_members', 'data_keys', 'collections', 'records',
                             'record_index', 'blobs', 'resource_grants'] LOOP
        EXECUTE format('CREATE POLICY app_boundary ON %I AS RESTRICTIVE TO strongbox_runtime
            USING (app = (SELECT sb_ctx_app()) AND (SELECT sb_ctx_admitted()))
            WITH CHECK (app = (SELECT sb_ctx_app()) AND (SELECT sb_ctx_admitted()))', t);
    END LOOP;
END $$;

-- Directory tables: readable inside the current app; admission reads them, so they must not
-- call sb_ctx_admitted() themselves.
CREATE POLICY read_app ON apps FOR SELECT TO strongbox_runtime USING (app = (SELECT sb_ctx_app()));
CREATE POLICY read_app ON app_clients FOR SELECT TO strongbox_runtime USING (app = (SELECT sb_ctx_app()));
CREATE POLICY read_app ON app_members FOR SELECT TO strongbox_runtime USING (app = (SELECT sb_ctx_app()));
-- Write policies are per command, never FOR ALL: a FOR ALL policy also applies to SELECT, and these
-- expressions read app_members/team_members themselves, which would recurse.
CREATE POLICY admin_adds ON app_members FOR INSERT TO strongbox_runtime
    WITH CHECK (app = (SELECT sb_ctx_app()) AND (SELECT sb_ctx_admitted()) AND (SELECT sb_ctx_app_role()) = 'admin');
CREATE POLICY admin_changes ON app_members FOR UPDATE TO strongbox_runtime
    USING (app = (SELECT sb_ctx_app()) AND (SELECT sb_ctx_admitted()) AND (SELECT sb_ctx_app_role()) = 'admin')
    WITH CHECK (app = (SELECT sb_ctx_app()) AND (SELECT sb_ctx_admitted()) AND (SELECT sb_ctx_app_role()) = 'admin');
CREATE POLICY admin_removes ON app_members FOR DELETE TO strongbox_runtime
    USING (app = (SELECT sb_ctx_app()) AND (SELECT sb_ctx_admitted()) AND (SELECT sb_ctx_app_role()) = 'admin');

CREATE POLICY read ON teams FOR SELECT TO strongbox_runtime USING (true);
CREATE POLICY creates ON teams FOR INSERT TO strongbox_runtime
    WITH CHECK (created_by = (SELECT sb_ctx_subject()) AND (SELECT sb_ctx_app_role()) IN ('member', 'editor', 'admin'));
CREATE POLICY manage ON teams FOR UPDATE TO strongbox_runtime
    USING ((SELECT sb_ctx_app_role()) = 'admin' OR id IN (SELECT t FROM sb_ctx_teams('admin') t))
    WITH CHECK ((SELECT sb_ctx_app_role()) = 'admin' OR id IN (SELECT t FROM sb_ctx_teams('admin') t));
CREATE POLICY remove ON teams FOR DELETE TO strongbox_runtime
    USING ((SELECT sb_ctx_app_role()) = 'admin' OR id IN (SELECT t FROM sb_ctx_teams('admin') t));

CREATE POLICY read ON team_members FOR SELECT TO strongbox_runtime USING (true);
CREATE POLICY adds ON team_members FOR INSERT TO strongbox_runtime
    WITH CHECK ((SELECT sb_ctx_app_role()) = 'admin' OR team_id IN (SELECT t FROM sb_ctx_teams('admin') t)
           OR team_id IN (SELECT id FROM teams WHERE created_by = (SELECT sb_ctx_subject())));
CREATE POLICY changes ON team_members FOR UPDATE TO strongbox_runtime
    USING ((SELECT sb_ctx_app_role()) = 'admin' OR team_id IN (SELECT t FROM sb_ctx_teams('admin') t)
           OR team_id IN (SELECT id FROM teams WHERE created_by = (SELECT sb_ctx_subject())))
    WITH CHECK ((SELECT sb_ctx_app_role()) = 'admin' OR team_id IN (SELECT t FROM sb_ctx_teams('admin') t)
           OR team_id IN (SELECT id FROM teams WHERE created_by = (SELECT sb_ctx_subject())));
CREATE POLICY removes ON team_members FOR DELETE TO strongbox_runtime
    USING ((SELECT sb_ctx_app_role()) = 'admin' OR team_id IN (SELECT t FROM sb_ctx_teams('admin') t)
           OR team_id IN (SELECT id FROM teams WHERE created_by = (SELECT sb_ctx_subject()))
           OR subject = (SELECT sb_ctx_subject()));

-- Wrapped data keys are not secrets without KMS; any admitted caller may read or create them.
CREATE POLICY use ON data_keys FOR SELECT TO strongbox_runtime USING (true);
CREATE POLICY creates ON data_keys FOR INSERT TO strongbox_runtime WITH CHECK (true);
CREATE POLICY retire ON data_keys FOR UPDATE TO strongbox_runtime
    USING ((SELECT sb_ctx_mode()) = 'worker') WITH CHECK ((SELECT sb_ctx_mode()) = 'worker');

CREATE POLICY read ON collections FOR SELECT TO strongbox_runtime USING (true);
CREATE POLICY define ON collections FOR INSERT TO strongbox_runtime
    WITH CHECK ((SELECT sb_ctx_mode()) = 'worker' OR (SELECT sb_ctx_app_role()) IN ('editor', 'admin'));
CREATE POLICY change ON collections FOR UPDATE TO strongbox_runtime
    USING ((SELECT sb_ctx_mode()) = 'worker' OR (SELECT sb_ctx_app_role()) IN ('editor', 'admin'))
    WITH CHECK ((SELECT sb_ctx_mode()) = 'worker' OR (SELECT sb_ctx_app_role()) IN ('editor', 'admin'));

-- Records and blobs: identical sharing rules.
DO $$
DECLARE t text; k text;
BEGIN
    FOR t, k IN SELECT * FROM (VALUES ('records', 'record'), ('blobs', 'blob')) v LOOP
        EXECUTE format($p$CREATE POLICY read ON %1$I FOR SELECT TO strongbox_runtime USING (
            (SELECT sb_ctx_mode()) = 'worker'
            OR owner = (SELECT sb_ctx_subject())
            OR visibility = 'app'
            OR (visibility = 'team' AND team_id IN (SELECT t FROM sb_ctx_teams('viewer') t))
            OR id IN (SELECT g FROM sb_ctx_granted(%2$L, 'viewer') g))$p$, t, k);
        EXECUTE format($p$CREATE POLICY edit ON %1$I FOR UPDATE TO strongbox_runtime USING (
            (SELECT sb_ctx_mode()) = 'worker'
            OR owner = (SELECT sb_ctx_subject())
            OR (visibility = 'app' AND (SELECT sb_ctx_app_role()) IN ('editor', 'admin'))
            OR (visibility = 'team' AND team_id IN (SELECT t FROM sb_ctx_teams('editor') t))
            OR id IN (SELECT g FROM sb_ctx_granted(%2$L, 'editor') g))
          WITH CHECK (
            (SELECT sb_ctx_mode()) = 'worker'
            OR owner = (SELECT sb_ctx_subject())
            OR (visibility = 'app' AND (SELECT sb_ctx_app_role()) IN ('editor', 'admin'))
            OR (visibility = 'team' AND team_id IN (SELECT t FROM sb_ctx_teams('editor') t))
            OR id IN (SELECT g FROM sb_ctx_granted(%2$L, 'editor') g))$p$, t, k);
        EXECUTE format($p$CREATE POLICY creates ON %1$I FOR INSERT TO strongbox_runtime WITH CHECK (
            (SELECT sb_ctx_mode()) = 'worker'
            OR (owner = (SELECT sb_ctx_subject())
                AND (SELECT sb_ctx_app_role()) IN ('member', 'editor', 'admin')
                AND (visibility <> 'team' OR team_id IN (SELECT t FROM sb_ctx_teams('viewer') t))))$p$, t);
        EXECUTE format($p$CREATE POLICY purge ON %1$I FOR DELETE TO strongbox_runtime
            USING (sb_can_manage(owner, visibility, team_id))$p$, t);
    END LOOP;
END $$;

-- Index rows follow the visibility of their record.
CREATE POLICY follows_record ON record_index FOR ALL TO strongbox_runtime
    USING (EXISTS (SELECT 1 FROM records r WHERE r.app = record_index.app AND r.id = record_index.record_id))
    WITH CHECK (EXISTS (SELECT 1 FROM records r WHERE r.app = record_index.app AND r.id = record_index.record_id));

-- Grants never consult records/blobs in their SELECT policy: the record read policy consults grants,
-- and a cycle would recurse at execution time.
CREATE POLICY read ON resource_grants FOR SELECT TO strongbox_runtime USING (
    subject = (SELECT sb_ctx_subject())
    OR team_id IN (SELECT t FROM sb_ctx_teams('viewer') t)
    OR granted_by = (SELECT sb_ctx_subject())
    OR resource_owner = (SELECT sb_ctx_subject())
    OR (SELECT sb_ctx_app_role()) = 'admin');
CREATE POLICY share ON resource_grants FOR INSERT TO strongbox_runtime WITH CHECK (
    granted_by = (SELECT sb_ctx_subject())
    AND (EXISTS (SELECT 1 FROM records r WHERE r.app = resource_grants.app AND r.id = resource_grants.record_id
                 AND r.owner = resource_grants.resource_owner
                 AND sb_can_share('record', r.id, r.owner, r.visibility, r.team_id)
                 AND (NOT resource_grants.can_share OR sb_can_manage(r.owner, r.visibility, r.team_id)))
      OR EXISTS (SELECT 1 FROM blobs b WHERE b.app = resource_grants.app AND b.id = resource_grants.blob_id
                 AND b.owner = resource_grants.resource_owner
                 AND sb_can_share('blob', b.id, b.owner, b.visibility, b.team_id)
                 AND (NOT resource_grants.can_share OR sb_can_manage(b.owner, b.visibility, b.team_id)))));
CREATE POLICY unshare ON resource_grants FOR DELETE TO strongbox_runtime USING (
    EXISTS (SELECT 1 FROM records r WHERE r.app = resource_grants.app AND r.id = resource_grants.record_id
            AND sb_can_share('record', r.id, r.owner, r.visibility, r.team_id))
    OR EXISTS (SELECT 1 FROM blobs b WHERE b.app = resource_grants.app AND b.id = resource_grants.blob_id
            AND sb_can_share('blob', b.id, b.owner, b.visibility, b.team_id)));

-- Audit: app chains are visible only inside their app; the global chain only in global mode.
-- The dispatcher may read chain heads (sequence numbers and hashes, no content).
CREATE POLICY own_chain ON audit_events FOR SELECT TO strongbox_runtime USING (
    CASE (SELECT sb_ctx_mode()) WHEN 'global' THEN app IS NULL WHEN 'dispatcher' THEN false
         ELSE app = (SELECT sb_ctx_app()) END);
CREATE POLICY append ON audit_events FOR INSERT TO strongbox_runtime WITH CHECK (
    CASE (SELECT sb_ctx_mode()) WHEN 'global' THEN app IS NULL WHEN 'dispatcher' THEN false
         ELSE app = (SELECT sb_ctx_app()) END);
CREATE POLICY own_chain ON audit_heads FOR ALL TO strongbox_runtime
    USING (CASE (SELECT sb_ctx_mode()) WHEN 'global' THEN app IS NULL WHEN 'dispatcher' THEN true
                ELSE app = (SELECT sb_ctx_app()) END)
    WITH CHECK (CASE (SELECT sb_ctx_mode()) WHEN 'global' THEN app IS NULL WHEN 'dispatcher' THEN false
                ELSE app = (SELECT sb_ctx_app()) END);

-- Privileges -----------------------------------------------------------------------------------
-- Explicit, column-level where it matters: app, owner, id and created_* are never writable by the
-- runtime role, so moving data between apps or changing an owner is a privileged operation.
-- No TRUNCATE, no REFERENCES, no TRIGGER; audit rows are append-only for the runtime.

DO $$
DECLARE t text;
BEGIN
    FOR t IN SELECT tablename FROM pg_tables WHERE schemaname = current_schema() AND tableowner = current_user LOOP
        EXECUTE format('REVOKE ALL ON %I FROM PUBLIC', t);
    END LOOP;
END $$;
REVOKE ALL ON FUNCTION sb_ctx_app(), sb_ctx_subject(), sb_ctx_actor(), sb_ctx_mode(), sb_ctx_app_role(),
    sb_ctx_admitted(), sb_ctx_teams(text), sb_ctx_granted(text, text), sb_can_manage(text, text, text),
    sb_can_share(text, text, text, text, text), sb_guard_resource_update() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION sb_ctx_app(), sb_ctx_subject(), sb_ctx_actor(), sb_ctx_mode(), sb_ctx_app_role(),
    sb_ctx_admitted(), sb_ctx_teams(text), sb_ctx_granted(text, text), sb_can_manage(text, text, text),
    sb_can_share(text, text, text, text, text), sb_guard_resource_update() TO strongbox_runtime;

GRANT SELECT ON schema_migrations TO strongbox_runtime; -- lets serve refuse to run against an unmigrated schema
GRANT SELECT, INSERT ON principals TO strongbox_runtime;
GRANT UPDATE (kind, display_name, scopes, us_person, cui_access, cui_categories, dissemination,
              llm_boundary_authorized, disabled, updated_at) ON principals TO strongbox_runtime;
GRANT SELECT ON apps, app_clients TO strongbox_runtime;
GRANT SELECT, INSERT, DELETE ON app_members TO strongbox_runtime;
GRANT UPDATE (role) ON app_members TO strongbox_runtime;
GRANT SELECT, INSERT, DELETE ON teams, team_members TO strongbox_runtime;
GRANT UPDATE (name) ON teams TO strongbox_runtime;
GRANT UPDATE (role) ON team_members TO strongbox_runtime;
GRANT SELECT, INSERT ON data_keys TO strongbox_runtime;
GRANT UPDATE (retired_at) ON data_keys TO strongbox_runtime;
GRANT SELECT, INSERT ON collections TO strongbox_runtime;
GRANT UPDATE (marking, indexed_fields, json_schema, version, updated_at) ON collections TO strongbox_runtime;
GRANT SELECT, INSERT, DELETE ON records TO strongbox_runtime;
GRANT UPDATE (marking, data_plain, data_sealed, key_id, version, updated_by, updated_at, deleted_at,
              visibility, team_id, aad_version) ON records TO strongbox_runtime;
GRANT SELECT, INSERT, DELETE ON record_index TO strongbox_runtime;
GRANT SELECT, INSERT, DELETE ON blobs TO strongbox_runtime;
GRANT UPDATE (state, size_bytes, ciphertext_sha256, wrapped_dek, deleted_at, shredded_at, visibility,
              team_id, lease_owner, lease_expires) ON blobs TO strongbox_runtime;
GRANT SELECT, INSERT, DELETE ON resource_grants TO strongbox_runtime;
GRANT UPDATE (role, can_share) ON resource_grants TO strongbox_runtime;
GRANT SELECT, INSERT ON audit_events TO strongbox_runtime;
GRANT SELECT, INSERT ON audit_heads TO strongbox_runtime;
GRANT UPDATE (seq, hash) ON audit_heads TO strongbox_runtime;
