-- Operation receipts, record history, the transactional outbox and audit delivery cursors.

SET LOCAL ROLE strongbox_owner;

-- Operation receipts --------------------------------------------------------------------------
-- One row per (app, subject, actor, op_id). The fingerprint is an HMAC under a per-app receipt key
-- of the operation type, target, expected version, marking and canonical payload digest, so a
-- database reader cannot test guesses of low-entropy payloads. Results hold IDs, versions and
-- states only, never content. A receipt is written in the same transaction as the mutation.
CREATE TABLE operation_receipts (
    app              text NOT NULL REFERENCES apps (app),
    subject          text NOT NULL,
    actor            text NOT NULL,
    op_id            text NOT NULL CHECK (op_id ~ '^[A-Za-z0-9._:~-]{8,128}$'),
    op_type          text NOT NULL,
    fingerprint      bytea NOT NULL,
    fp_key_id        text NOT NULL,
    status           text NOT NULL CHECK (status IN ('pending', 'succeeded')),
    resource_type    text,
    resource_id      text,
    resource_version integer,
    result           jsonb NOT NULL DEFAULT '{}',
    lease_owner      text,
    lease_expires    timestamptz,
    created_at       timestamptz NOT NULL DEFAULT now(),
    completed_at     timestamptz,
    expires_at       timestamptz NOT NULL,
    PRIMARY KEY (app, subject, actor, op_id),
    FOREIGN KEY (app, fp_key_id) REFERENCES data_keys (app, id) DEFERRABLE
);
CREATE INDEX ix_receipts_expiry ON operation_receipts (app, expires_at);

-- Record history -------------------------------------------------------------------------------
-- Every committed version, written in the mutating transaction. Sealed revisions reuse the record
-- ciphertext of that version (its AAD binds collection, id, marking and version). Delete
-- revisions carry no content.
CREATE TABLE record_revisions (
    app         text NOT NULL,
    record_id   text NOT NULL,
    version     integer NOT NULL,
    collection  text NOT NULL,
    marking     text NOT NULL,
    op          text NOT NULL CHECK (op IN ('create', 'update', 'delete', 'restore')),
    data_plain  jsonb,
    data_sealed bytea,
    key_id      text,
    aad_version smallint NOT NULL,
    size_bytes  integer NOT NULL,
    subject     text NOT NULL,
    actor       text NOT NULL,
    created_at  timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (app, record_id, version),
    FOREIGN KEY (app, record_id) REFERENCES records (app, id) ON DELETE CASCADE DEFERRABLE,
    FOREIGN KEY (app, key_id) REFERENCES data_keys (app, id) DEFERRABLE,
    CHECK (data_plain IS NULL OR marking = 'UNCONTROLLED'),
    CHECK ((op = 'delete') = (data_plain IS NULL AND data_sealed IS NULL))
);
CREATE INDEX ix_revisions_age ON record_revisions (app, created_at);

-- A deleted record keeps no content in its live row; the content stays in history until history
-- expiry or purge (docs/RETENTION.md).
ALTER TABLE records DROP CONSTRAINT records_check;
ALTER TABLE records ADD CONSTRAINT records_content CHECK (
    (deleted_at IS NOT NULL AND data_plain IS NULL AND data_sealed IS NULL)
    OR ((data_plain IS NULL) <> (data_sealed IS NULL))) NOT VALID;
ALTER TABLE collections ADD COLUMN history_limit integer NOT NULL DEFAULT 100 CHECK (history_limit BETWEEN 1 AND 10000);

-- Outbox ---------------------------------------------------------------------------------------
-- Side effects outside Postgres (object deletion) are enqueued in the transaction that causes
-- them and executed afterwards by the worker: at-least-once, with leases, bounded retries and a
-- dead state. Payloads carry scoped IDs only. The id is allocated at insert, not at commit, so it
-- is not a commit-order cursor (docs/ARCHITECTURE.md#outbox).
CREATE TABLE outbox (
    id            bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    app           text NOT NULL REFERENCES apps (app),
    kind          text NOT NULL CHECK (kind IN ('object.delete')),
    payload       jsonb NOT NULL,
    status        text NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'leased', 'done', 'dead')),
    attempts      integer NOT NULL DEFAULT 0,
    max_attempts  integer NOT NULL DEFAULT 10,
    available_at  timestamptz NOT NULL DEFAULT now(),
    lease_owner   text,
    lease_expires timestamptz,
    last_error    text,
    created_at    timestamptz NOT NULL DEFAULT now(),
    updated_at    timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX ix_outbox_ready ON outbox (available_at, id) WHERE status IN ('pending', 'leased');
CREATE INDEX ix_outbox_app ON outbox (app, status);

CREATE TABLE audit_delivery (
    chain         text PRIMARY KEY REFERENCES audit_heads (chain),
    app           text REFERENCES apps (app),
    delivered_seq bigint NOT NULL DEFAULT 0,
    updated_at    timestamptz
);

-- Policies -------------------------------------------------------------------------------------

ALTER TABLE operation_receipts ENABLE ROW LEVEL SECURITY;
ALTER TABLE operation_receipts FORCE ROW LEVEL SECURITY;
CREATE POLICY maintenance ON operation_receipts TO strongbox_owner USING (true) WITH CHECK (true);
CREATE POLICY app_boundary ON operation_receipts AS RESTRICTIVE TO strongbox_runtime
    USING (app = (SELECT sb_ctx_app()) AND (SELECT sb_ctx_admitted()))
    WITH CHECK (app = (SELECT sb_ctx_app()) AND (SELECT sb_ctx_admitted()));
-- A receipt belongs to the exact (subject, actor) pair: an agent acting for a user does not share
-- receipts with the user acting directly.
CREATE POLICY own_read ON operation_receipts FOR SELECT TO strongbox_runtime USING (
    (SELECT sb_ctx_mode()) = 'worker' OR (subject = (SELECT sb_ctx_subject()) AND actor = (SELECT sb_ctx_actor())));
CREATE POLICY own_write ON operation_receipts FOR INSERT TO strongbox_runtime WITH CHECK (
    subject = (SELECT sb_ctx_subject()) AND actor = (SELECT sb_ctx_actor()));
CREATE POLICY own_complete ON operation_receipts FOR UPDATE TO strongbox_runtime
    USING (subject = (SELECT sb_ctx_subject()) AND actor = (SELECT sb_ctx_actor()))
    WITH CHECK (subject = (SELECT sb_ctx_subject()) AND actor = (SELECT sb_ctx_actor()));
CREATE POLICY expire ON operation_receipts FOR DELETE TO strongbox_runtime USING ((SELECT sb_ctx_mode()) = 'worker');

ALTER TABLE record_revisions ENABLE ROW LEVEL SECURITY;
ALTER TABLE record_revisions FORCE ROW LEVEL SECURITY;
CREATE POLICY maintenance ON record_revisions TO strongbox_owner USING (true) WITH CHECK (true);
CREATE POLICY app_boundary ON record_revisions AS RESTRICTIVE TO strongbox_runtime
    USING (app = (SELECT sb_ctx_app()) AND (SELECT sb_ctx_admitted()))
    WITH CHECK (app = (SELECT sb_ctx_app()) AND (SELECT sb_ctx_admitted()));
CREATE POLICY follows_record ON record_revisions FOR SELECT TO strongbox_runtime
    USING (EXISTS (SELECT 1 FROM records r WHERE r.app = record_revisions.app AND r.id = record_revisions.record_id));
CREATE POLICY written_with_record ON record_revisions FOR INSERT TO strongbox_runtime
    WITH CHECK (EXISTS (SELECT 1 FROM records r WHERE r.app = record_revisions.app AND r.id = record_revisions.record_id));
CREATE POLICY prune ON record_revisions FOR DELETE TO strongbox_runtime USING ((SELECT sb_ctx_mode()) = 'worker');

ALTER TABLE outbox ENABLE ROW LEVEL SECURITY;
ALTER TABLE outbox FORCE ROW LEVEL SECURITY;
CREATE POLICY maintenance ON outbox TO strongbox_owner USING (true) WITH CHECK (true);
CREATE POLICY enqueue ON outbox FOR INSERT TO strongbox_runtime
    WITH CHECK ((SELECT sb_ctx_mode()) IN ('app', 'worker') AND app = (SELECT sb_ctx_app()));
CREATE POLICY dispatch ON outbox FOR SELECT TO strongbox_runtime
    USING (CASE (SELECT sb_ctx_mode()) WHEN 'dispatcher' THEN true WHEN 'worker' THEN app = (SELECT sb_ctx_app()) ELSE false END);
CREATE POLICY lease ON outbox FOR UPDATE TO strongbox_runtime
    USING ((SELECT sb_ctx_mode()) = 'dispatcher') WITH CHECK ((SELECT sb_ctx_mode()) = 'dispatcher');

ALTER TABLE audit_delivery ENABLE ROW LEVEL SECURITY;
ALTER TABLE audit_delivery FORCE ROW LEVEL SECURITY;
CREATE POLICY maintenance ON audit_delivery TO strongbox_owner USING (true) WITH CHECK (true);
CREATE POLICY own_chain ON audit_delivery FOR ALL TO strongbox_runtime
    USING (CASE (SELECT sb_ctx_mode()) WHEN 'global' THEN app IS NULL WHEN 'dispatcher' THEN true
                ELSE app = (SELECT sb_ctx_app()) END)
    WITH CHECK (CASE (SELECT sb_ctx_mode()) WHEN 'global' THEN app IS NULL WHEN 'dispatcher' THEN false
                ELSE app = (SELECT sb_ctx_app()) END);

-- The dispatcher enumerates apps (identifiers only) to run per-app maintenance in worker mode.
-- CASE, not OR: the app reader raises when no app is set, and OR does not fix evaluation order.
DROP POLICY read_app ON apps;
CREATE POLICY read_app ON apps FOR SELECT TO strongbox_runtime
    USING (CASE (SELECT sb_ctx_mode()) WHEN 'dispatcher' THEN true ELSE app = (SELECT sb_ctx_app()) END);

REVOKE ALL ON operation_receipts, record_revisions, outbox, audit_delivery FROM PUBLIC;
GRANT SELECT, INSERT, DELETE ON operation_receipts TO strongbox_runtime;
GRANT UPDATE (status, resource_type, resource_id, resource_version, result, lease_owner, lease_expires, completed_at)
    ON operation_receipts TO strongbox_runtime;
GRANT SELECT, INSERT, DELETE ON record_revisions TO strongbox_runtime;
GRANT SELECT, INSERT ON outbox TO strongbox_runtime;
GRANT UPDATE (status, attempts, available_at, lease_owner, lease_expires, last_error, updated_at) ON outbox TO strongbox_runtime;
GRANT SELECT, INSERT ON audit_delivery TO strongbox_runtime;
GRANT UPDATE (delivered_seq, updated_at) ON audit_delivery TO strongbox_runtime;
GRANT UPDATE (history_limit) ON collections TO strongbox_runtime;
