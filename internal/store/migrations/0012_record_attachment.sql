SET LOCAL ROLE strongbox_owner;

-- A live link pins the blob's active state. Updating state (including shred) conflicts
-- with the FK even when linking and deleting race in different transactions.
ALTER TABLE blobs ADD CONSTRAINT blobs_attachment_key UNIQUE (app, id, owner, state);
ALTER TABLE records ADD COLUMN attachment_id text,
    ADD COLUMN attachment_state text NOT NULL DEFAULT 'active' CHECK (attachment_state = 'active'),
    ADD CONSTRAINT active_record_attachment FOREIGN KEY (app, attachment_id, owner, attachment_state)
        REFERENCES blobs (app, id, owner, state) DEFERRABLE INITIALLY IMMEDIATE,
    ADD CHECK (deleted_at IS NULL OR attachment_id IS NULL);
CREATE INDEX ix_records_attachment ON records (app, attachment_id) WHERE attachment_id IS NOT NULL;
ALTER TABLE record_revisions ADD COLUMN attachment_id text;
GRANT UPDATE (attachment_id) ON records TO strongbox_runtime;

CREATE FUNCTION sb_guard_attachment_update() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF NEW.attachment_id IS DISTINCT FROM OLD.attachment_id AND NEW.deleted_at IS NULL
        AND current_user <> 'strongbox_owner' AND row_security_active(TG_RELID::regclass)
        AND sb_ctx_subject() <> OLD.owner THEN
        RAISE EXCEPTION 'only the record owner can change its attachment' USING ERRCODE = '42501';
    END IF;
    RETURN NEW;
END $$;
CREATE TRIGGER guard_attachment BEFORE UPDATE OF attachment_id ON records
    FOR EACH ROW EXECUTE FUNCTION sb_guard_attachment_update();
REVOKE ALL ON FUNCTION sb_guard_attachment_update() FROM PUBLIC;
