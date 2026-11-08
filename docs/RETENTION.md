# Retention: what deleting actually does

Strongbox has five separate mechanisms that remove data. They act on different copies, on different
schedules. None of them, alone, makes data unrecoverable everywhere. This page says exactly what
each one does so retention schedules and sanitization claims can be written accurately.

| Mechanism | Trigger | What is removed | What still exists afterwards |
|---|---|---|---|
| **Delete** (record) | `DELETE …/records/{id}` | The live row's content and its equality-index tokens, in the same transaction. The row stays as a tombstone (no content) and the record leaves every listing. | The record's history (sealed revisions) until deleted-record expiry or purge; database backups. |
| **Delete** (blob) | `DELETE …/blobs/{id}` | The blob leaves listings at once. After `DeleteGrace`, the worker deletes every object of the blob (single object or all parts), marks the row `purged` and drops its wrapped data key from the live row. | Noncurrent object versions in the bucket until they expire; database backups (which hold the wrapped key). |
| **Purge** (record) | `DELETE …/records/{id}?purge=true`, or deleted-record expiry | The row and all of its revisions, in one transaction. | Database backups. |
| **Shred** (blob) | `DELETE …/blobs/{id}?shred=true` | As delete, plus the wrapped data key is nulled **in the same transaction** as the delete (not after the grace period). | Database backups that predate the shred still hold the wrapped key; noncurrent object versions still hold ciphertext. |
| **History expiry** | Every record write | Revisions older than the collection's `history_limit` (default 100 versions) for that record. | Database backups. Lowering `history_limit` applies to each record on its next write. |
| **Deleted-record expiry** | Worker, each pass | Records deleted more than `deleted_retention_days` (default 30) ago are purged with their history, up to 500 per app per pass. Each purge is audited. | Database backups. |
| **Backup expiry** | Cloud SQL and the bucket | Cloud SQL automated backups age out (7 by default) and point-in-time recovery logs age out (7 days by default). Noncurrent object versions age out after `blob_noncurrent_retention_days` (Terraform, default 30). Soft-deleted objects age out after 7 days. | Exports and copies made outside Strongbox. |

## When is a blob unrecoverable?

Decrypting a blob needs both its ciphertext and its wrapped data key (and the KMS key version that
wrapped it). After a **shred**:

- the live database has no wrapped key, so no request can read the blob;
- the ciphertext is deleted by the worker; older object versions remain until bucket lifecycle
  removes them;
- every database backup and point-in-time recovery window taken before the shred still contains the
  wrapped key.

So the blob is unrecoverable through Strongbox immediately, and unrecoverable by anyone once **either**
every database backup holding the wrapped key has expired **or** every copy of the ciphertext has
expired, whichever comes first. With the defaults that is at most 30 days. Destroying the KMS key
version that wrapped the key also ends recovery, but that affects every object wrapped by that
version, so it is a whole-system decision, not a per-object one.

Earlier documentation said shredding made "every other copy permanently undecryptable" at once.
That was wrong while backups held the wrapped key, and has been corrected here and in
[SECURITY.md](SECURITY.md).

## Records

Record content is sealed with per-app collection data keys that rotate weekly and are never
destroyed (old keys are needed to read old versions). There is therefore no per-record shred:
removing a record means removing its rows (purge), and the content remains in database backups until
they expire. If a record must be unrecoverable sooner than backup expiry, the options are a shorter
backup retention for the instance or a separate collection (and instance) with its own retention.

## Operation receipts and audit

- Operation receipts hold IDs, versions and keyed digests, never content. They expire after seven
  days (the window in which a lost response can be recovered).
- Audit events hold IDs, markings and reasons, never content. They are not removed by any mechanism
  above. Their retention is the locked Cloud Logging bucket's (`retention_days`, default ~7 years)
  and the database's (no automatic expiry; archive and truncate chains only through a reviewed
  operator procedure, since truncation breaks hash-chain verification from the start).

## Settings

| Setting | Where | Default |
|---|---|---|
| `history_limit` | collection | 100 versions |
| `deleted_retention_days` | collection | 30 days |
| `DeleteGrace` (object deletion delay after a blob delete) | service | 0 (next worker pass) |
| Receipt lifetime | service | 7 days |
| Cloud SQL backups / PITR | Terraform (`backup_configuration`) | 7 backups / 7 days |
| `blob_noncurrent_retention_days` | Terraform | 30 days |
| Bucket soft delete | Terraform (`soft_delete_policy`) | 7 days |
| Audit log bucket | Terraform (`google_logging_project_bucket_config.audit`) | 2555 days, lock after confirming |

Unexpired operation receipts pin the record revisions needed for replay during ordinary history
trimming (seven-day receipt lifetime). This can temporarily exceed `history_limit`. Explicit
purge and deleted-record expiry still remove data; a receipt cannot resurrect purged content or
bypass current access checks. Old receipt keys must remain decryptable until their receipts expire.
