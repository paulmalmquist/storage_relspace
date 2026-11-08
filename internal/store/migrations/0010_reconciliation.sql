SET LOCAL ROLE strongbox_owner;
ALTER TABLE outbox DROP CONSTRAINT outbox_kind_check;
ALTER TABLE outbox ADD CONSTRAINT outbox_kind_check CHECK(kind IN ('object.delete','object.orphan_delete'));
-- Repeated scans may observe the same unreferenced generation before the worker runs.
CREATE UNIQUE INDEX ux_outbox_orphan_generation ON outbox(app,(payload->>'key'),(payload->>'version'))
    WHERE kind='object.orphan_delete' AND status IN ('pending','leased');

CREATE INDEX ix_blobs_object_reference ON blobs(app,storage_key) WHERE state<>'purged';
CREATE INDEX ix_blob_parts_object_reference ON blob_parts(app,storage_key);
