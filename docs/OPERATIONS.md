# Operations

Runbook for a Strongbox deployment on Cloud Run, Cloud SQL for PostgreSQL 16, GCS and Cloud KMS
(Terraform in [infra/terraform](../infra/terraform)). Commands are `strongbox <command>`; the
migration login is `STRONGBOX_MIGRATION_DATABASE_URL`, the runtime login `STRONGBOX_DATABASE_URL`.

## First deployment

1. `terraform apply`. This creates two Cloud SQL IAM users: `<name>-api` (runtime) and
   `<name>-migrate` (migrations and admin commands).
2. **One time:** give the migration login `CREATEROLE` so it can create Strongbox's roles. Connect
   as the built-in `postgres` user (`gcloud sql connect <instance> --user=postgres`) and run:

   ```sql
   GRANT cloudsqlsuperuser TO "<name>-migrate@<project>.iam";
   ```

   After the first `init` you may revoke it again; later migrations only need membership in
   `strongbox_owner`, which `init` grants.
3. Run the `<name>-migrate` Cloud Run job. It runs
   `strongbox init -bootstrap-roles -runtime-login <name>-api@<project>.iam`, which creates
   `strongbox_owner` and `strongbox_runtime`, the `strongbox` schema owned by `strongbox_owner`,
   grants `strongbox_runtime` (and nothing else) to the API login, and applies migrations.
4. Deploy the API service. `serve` checks its login (`strongbox db check-roles` shows the same
   report) and refuses to start if the login is a superuser, has `BYPASSRLS`, `CREATEROLE` or
   `CREATEDB`, belongs to `strongbox_owner` or any privileged role, owns objects, or can create in
   the schema or database. It also refuses a schema older than the build.
5. Register principals and create apps, from the migration job or a workstation with the migration
   login:

   ```bash
   strongbox principal put alice@example.com -scope records:read -scope records:write -scope blobs:read \
     -scope blobs:write -scope collections:admin -scope apps:manage -us-person -cui-access -category SP-EXPT
   strongbox principal put notes-backend@proj.iam.gserviceaccount.com -kind service -scope delegate \
     -scope records:read -scope records:write -scope blobs:read -scope blobs:write
   strongbox admin app create notes:prod -name "Notes" -admin alice@example.com
   strongbox admin client add notes:prod notes-backend@proj.iam.gserviceaccount.com
   strongbox admin quota set notes:prod -max-blob-bytes 107374182400 -max-records 5000000
   ```

## Migrations

Migrations are numbered SQL files embedded in the binary, applied in order under an advisory lock,
each in its own transaction, as `strongbox_owner`. They are additive: new columns are nullable or
have constant defaults, constraints on existing data are added `NOT VALID`, and nothing rewrites a
table at startup. Run the migrate job **before** deploying a build that needs the new schema;
`serve` refuses to start until it has run. `strongbox db status` prints applied and embedded versions.

Data moved into apps by `0002` stays in the invisible `_legacy` scope until assigned:

```bash
strongbox admin legacy-assign -app notes:prod -dry-run    # counts and verifies, writes nothing
strongbox admin legacy-assign -app notes:prod             # moves everything in one transaction
```

`legacy-assign` decrypts every legacy ciphertext under its original context first (`-verify`,
default on) and seals any controlled record still stored in plaintext. It needs KMS access, which the
migration identity does not have by default: run it as an operator identity granted
`roles/cloudkms.cryptoKeyEncrypterDecrypter` on the data KEK for the duration.

## Capacity and budgets

| Setting | Default | Notes |
|---|---|---|
| `STRONGBOX_DB_MAX_CONNS` (Terraform `db_pool_size`) | 10 | Per instance. `api_max_instances × db_pool_size + 10` must not exceed Cloud SQL `max_connections`; Terraform checks this. |
| `STRONGBOX_DB_MAX_CONNS_PER_APP` | half the pool | Connections one app's transactions may hold at once, so a busy app queues behind its own share ([LOAD.md](evidence/LOAD.md) shows why). |
| `STRONGBOX_DB_ACQUIRE_TIMEOUT_MS` | 3000 | A request that waits longer for a connection gets `503` with `Retry-After`, instead of queueing. |
| `STRONGBOX_DB_STATEMENT_TIMEOUT_MS` | 15000 | Per statement (also `idle_in_transaction_session_timeout`). |
| `STRONGBOX_REQUEST_TIMEOUT_MS` | 30000 | Non-streaming requests. Uploads, downloads and parts are bounded by Cloud Run's request timeout (300 s in Terraform). |
| `STRONGBOX_KMS_TIMEOUT_MS` | 10000 | Each wrap/unwrap. |
| Cloud Run `max_instance_request_concurrency` (`api_concurrency`) | 40 | Keep it a small multiple of the pool size. |
| `STRONGBOX_RATE_SUBJECT_PER_SECOND` / `_BURST` | 50 / 100 | Per (app, subject), per instance. |
| `STRONGBOX_RATE_APP_PER_SECOND` / `_BURST` | 500 / 1000 | Per app, per instance. |
| `STRONGBOX_MAX_IN_FLIGHT_PER_APP` | 64 | Concurrent requests per app, per instance, so one app cannot take every connection. |
| `STRONGBOX_MAX_SINGLE_UPLOAD_BYTES` | 16 MiB | One-request uploads. Must stay under Cloud Run's 32 MiB HTTP/1 request limit. |
| `STRONGBOX_UPLOAD_PART_BYTES` | 8 MiB | Upload-session part size (a multiple of the 64 KiB segment). |
| `STRONGBOX_MAX_BLOB_BYTES` | 5 GiB | Largest blob, through an upload session. |
| `STRONGBOX_UPLOAD_SESSION_TTL_SECONDS` | 86400 | A session with no part for this long is aborted by the worker and its reservation released. |

Rate limits are per process. With N instances the cluster-wide ceiling is N times each value; Cloud
Run's `max_instance_count` bounds N. There is no shared limiter (no Redis) by design: the per-app
quotas in the database are the durable limit; the rate limits protect each instance.

**Quotas** (`strongbox admin quota set APP …`) are enforced by database triggers on every write:

- blob bytes and blob count: exact. A one-request upload reserves its `Content-Length` (or the
  single-upload maximum when the length is unknown); an upload session reserves its declared size.
  Reservations are released when the upload commits (replaced by the actual size) or aborts.
- record count and record bytes (live records only; history is bounded separately by
  `history_limit` and deleted-record expiry): counters are sharded eight ways, so concurrent writers
  on other shards can exceed the limit by at most seven records.

`strongbox usage -app APP -recount` compares the counters with a full scan; `-fix` rewrites them.

## Keys

**KEK rotation.** Cloud KMS rotates the data KEK every 90 days (`kek_rotation_period`). New wraps use
the primary version; unwraps use the version recorded with each wrapped key. Keep old versions
enabled. Destroying a version makes every key it wrapped unrecoverable (see
[RETENTION.md](RETENTION.md)).

**Data-key rotation.** Per-app record and metadata data keys rotate every
`STRONGBOX_DATA_KEY_ROTATION_SECONDS` (7 days). Rotation happens on write: the next seal after
expiry creates a new key; old keys stay for reading. Blind-index keys never rotate (tokens must stay
comparable); changing one requires re-indexing the collection.

**Cache.** Unwrapped data keys are cached in memory per instance for
`STRONGBOX_DATA_KEY_CACHE_TTL_SECONDS` (300), at most 4096 entries, with concurrent misses for one
key coalesced into one KMS call.

**KMS failure.** Requests that need an uncached unwrap (most blob reads, the first record read per
key per instance after the TTL) fail with `503 unavailable` and `Retry-After`. Cached keys keep
serving records until their TTL. Writes that need a new data key or a blob DEK fail with `503`.
Nothing is written partially: the transaction rolls back. Watch `strongbox.kms.duration` with
`outcome=error`. To ride out a longer KMS outage for reads, raise the cache TTL (a security trade:
unwrapped keys live longer in memory).

## Worker

The worker runs inside every `serve` instance (Terraform sets CPU always allocated) and can run alone
as `strongbox worker`. Each pass: dispatch outbox jobs (object deletion), then per app abort expired
uploads, purge expired deleted records and drop expired receipts (at most 500 rows per statement),
then deliver audit events to the log. Any number of workers can run; jobs are leased with
`FOR UPDATE SKIP LOCKED`.

- `strongbox worker -once` runs one pass and prints its counters.
- Jobs that fail back off exponentially; after `max_attempts` (10) they are `dead` and stay in the
  `outbox` table. `strongbox.outbox.dead` counts them. Inspect with
  `SELECT id, app, kind, attempts, last_error FROM outbox WHERE status = 'dead'` as the migration
  login; to retry, set `status = 'pending', attempts = 0`.
- Finished jobs are deleted after a day.

## Metrics

With `STRONGBOX_METRICS_EXPORTER=gcp` (Terraform default) metrics go to Cloud Monitoring every
minute under the runtime service account (`roles/monitoring.metricWriter`). Labels are limited to
route templates, methods, status codes, error codes, operation kinds and outcomes: never app IDs,
subjects, resource IDs or markings.

| Metric | Use |
|---|---|
| `http.server.request.duration` | p95/p99 by route |
| `strongbox.errors{code}` | `unavailable`, `rate_limited`, `quota_exceeded`, `precondition_failed` (conflicts), `integrity_violation` |
| `strongbox.db.pool.wait`, `strongbox.db.pool.connections{state}` | pool saturation |
| `strongbox.kms.duration{op,outcome}` | KMS latency and failures |
| `strongbox.operation.replays{code}` | retried operations answered from receipts |
| `strongbox.outbox.lag`, `strongbox.outbox.dead`, `strongbox.outbox.jobs` | background work health |
| `strongbox.audit.backlog`, `strongbox.audit.delivered` | audit delivery lag |
| `strongbox.rate_limited{code}`, `strongbox.auth.audit_suppressed` | budget pressure, auth-failure floods |
| `strongbox.cache.lookups{result}`, `strongbox.runtime.heap`, `strongbox.runtime.goroutines` | memory |

Suggested alerts: any `integrity_violation`; `strongbox.outbox.dead > 0`; audit backlog growing for
15 minutes; `unavailable` above 1% of requests; `audit-verify` failing.

## Inventory, export and restore

```bash
strongbox inventory                                  # every app: usage, collections, contract versions, pending work
strongbox usage -app notes:prod -recount             # counters against a full scan; -fix rewrites drifted counters
strongbox export -app notes:prod -out /secure/notes-2026-11-07
strongbox validate-export -in /secure/notes-2026-11-07   # offline: digests, row counts, every blob's objects
```

An export (format version 1, see `internal/backup`) holds one app's rows, read from one database
snapshot, and its encrypted objects, with SHA-256 digests in `manifest.json`. This format is not
ciphertext-only: unencrypted UNCONTROLLED records, revisions and plain equality tokens remain
plaintext (review finding M10). Membership, schemas and audit metadata are also readable. Current
ciphertexts bind the app; assigned legacy ciphertexts retain their older contexts. Protect the
entire export according to its data classification.

Restore runs with the **target's** configuration (database, bucket, KMS):

```bash
strongbox init                                       # target at the build's schema version
strongbox restore -in /secure/notes-2026-11-07 -dry-run   # every row inserted and checked, then rolled back
strongbox restore -in /secure/notes-2026-11-07 -deep      # restore, then decrypt everything and verify chains and usage
```

Restore refuses a target that is the export's source database and schema, one that already has the
app, and one at an older schema than the export. It validates the export first and refuses a
mismatch. Objects are copied before rows are committed; a copy failure rolls back the rows and can leave
unreferenced objects in the target. Row scopes, canonical manifest paths and
object prefixes are checked before writing. In a populated target, every source principal must
already be provisioned by the target operator; existing policy is preserved. A genuinely empty
target can recover the source principals. Offline validation still misses an active multipart
blob whose part list has been removed; deep verification detects its missing stream (M11).

Restoring under a different app ID (a clone) is not supported: every ciphertext would have to be
re-sealed under the new app's contexts, which is a separate operation from restore.

## Audit

`strongbox audit-verify [-app APP]` (migration login) checks every hash chain. A failure names the
chain and the first bad sequence number. The worker delivers committed events to the structured log
(`jsonPayload.audit=true`), which the Terraform sink routes to the audit log bucket. The bucket is
initially unlocked (`locked = false`); retention becomes immutable only after the operator locks it.
