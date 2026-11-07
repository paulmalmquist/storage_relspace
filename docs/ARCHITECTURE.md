# Architecture

Strongbox is a shared persistence service for Dreamcatcher apps. Apps store personal state, team
records, app-wide data and encrypted attachments through one Go service. The service owns the
database and object store; apps get an HTTP API (and agents get MCP), never database credentials.

## Principles

1. **One enforcement core.** The REST API and the MCP server reach data only through
   `internal/service`. Every call is authenticated, authorized against the caller's clearances and
   sharing rights, executed in one database transaction, and audited in that same transaction. The
   MCP server is an API client, so it cannot skip any of it.
2. **The app boundary is enforced twice.** The service scopes every query to one app, and
   PostgreSQL row-level security independently refuses rows outside that app or outside the caller's
   sharing rights. A missing `WHERE` clause or a wrong ID fails closed.
3. **Encrypt in the application.** Storage-level CMEK protects disks and backups. Application
   envelope encryption also protects against database administrators, SQL injection, bucket ACL
   mistakes and leaked dumps, because none of those paths hold an unwrapped key.
4. **Markings are data with integrity.** A CUI banner travels with every object, is bound into its
   ciphertext, is enforced on every read, and is echoed on every response.
5. **Identity from tokens, rights from the database.** Tokens prove who is calling. Clearances come
   from the principal registry; app membership, team membership and grants come from app tables.
   Nothing a caller sends in a URL, header or body grants access.

## Trust boundary

| Component | Holds | Can do |
|---|---|---|
| App (browser, server, agent) | Its own OIDC token; optionally a user's token for delegation | Call `/v1/apps/{app}/…` as itself or for a user. No database, KMS or bucket access. |
| MCP server | Its service identity | Call the API with `X-On-Behalf-Of`. No database, KMS or bucket access. |
| API / worker (`strongbox serve`) | Runtime database login, KMS encrypt/decrypt, bucket object access | Everything the service code allows. Cannot bypass RLS, change policies, truncate, or create schemas. |
| Migrations and admin (`strongbox init`, `strongbox admin`) | Migration login (member of `strongbox_owner`) | Owns the schema. Runs migrations, creates apps, recovery. No KMS access unless an operator grants it for `legacy-assign`. |

Stated plainly: **RLS does not protect against a compromised API process.** The service sets the
request context (`strongbox.app`, `strongbox.subject`, `strongbox.actor`, `strongbox.mode`) with
`set_config(…, true)` after it verifies the caller. Those settings are not credentials. Code that
holds the runtime login can set any context and read anything that context admits. What RLS adds is
defense against bugs inside a correct process: a forgotten filter, a cross-app join, an ID taken
from another app, or a query run without context (which raises `42501` instead of returning rows).
It also means the runtime login itself cannot bypass policies, `TRUNCATE`, alter tables, create
schemas, or move rows between apps or owners (those columns are not granted). Protection against a
compromised process comes from what that process can reach: KMS IAM, VPC Service Controls, a
restricted bucket, and an audit log in a separate locked sink.

## App model

```
app  = <app_id>:<env>          e.g. notes:prod. URL names app_id; the deployment fixes env.
subject                         the principal the request is for (a user or a workload)
actor                           who sent it (equal to subject, or a registered client of the app)
member role                     viewer < member < editor < admin, per app
team                            a group inside one app; team roles viewer < editor < admin
resource                        a record or blob: owner, visibility (private | team | app), team_id
grant                           (resource, subject or team, viewer | editor, can_share)
```

A request is **admitted** to an app when the app is active, the subject is a member, and the actor
is either the subject or a client registered to that app (`strongbox admin client add`). Admission
is checked in SQL (`sb_ctx_admitted()`), so a token that is valid in one app is useless in another.
The environment never comes from the request: a `notes:prod` deployment cannot be asked for
`notes:dev` rows.

**Default is private.** New records and blobs are owned by the subject with `visibility = private`.
Sharing is explicit:

| Permission | Who has it |
|---|---|
| Read | owner; everyone admitted (visibility `app`); team members (visibility `team`); grantees |
| Write | owner; editors and admins (`app`); team editors and admins (`team`); `editor` grantees |
| Share (add or remove grants) | managers; grantees with `can_share` |
| Manage (delete, change visibility) | owner; app admins (`app`); team admins (`team`) |

Sharing is separate from editing: an editor cannot change visibility or grant access. Only a
manager can give out `can_share`. Clearances still apply after sharing: a grant never lets a
non-U.S. person read a NOFORN record, and an owner cannot override a marking's controls (markings
can only be raised by `Combine`, never lowered).

`internal/service/authz.go` implements these rules for the service (`Authorizer`), and RLS
implements them for the database. `TestAuthorizerMatchesRLS` checks the two agree across a matrix of
roles, visibilities and grants. The `Authorizer` interface is narrow (`Permissions(ctx, tx, access,
resource)`), so an OpenFGA or SpiceDB check could replace it later without touching callers.

**Explain.** `POST /v1/apps/{app}/explain` with `{"subject", "kind", "id"}` (app admins with
`apps:manage`) returns a subject's permissions on a resource with reason codes. Sharing codes are
`owner`, `app_visibility`, `app_role:<role>`, `team_role:<role>`, `grant:<role>`,
`team_grant:<role>`, `grant:can_share`, `not_shared_with_subject` and `not_app_member`. Clearance
codes come from the policy engine, for example `noforn_requires_us_person`, `missing_scope` or
`llm_boundary_not_authorized`. A resource the asking admin cannot see returns `404`.

## Database roles and row-level security

| Role | Purpose |
|---|---|
| `strongbox_owner` (NOLOGIN) | Owns every table, function and policy. The migration login is a member. Has a `maintenance` policy `USING (true)` on each table. |
| `strongbox_runtime` (NOLOGIN) | Holds the service's grants: column-level `UPDATE` (never `app`, `owner`, `id` or `created_*`), no `TRUNCATE`, `REFERENCES` or `TRIGGER`, append-only audit. |
| runtime login | A member of `strongbox_runtime` only. `strongbox serve` refuses to start if the login is a superuser, has `BYPASSRLS`, `CREATEROLE` or `CREATEDB`, is a member of the owner role or another privileged role, owns objects, or can create in the schema or database (`store.CheckRuntime`). |

Every app table has `ENABLE` and `FORCE ROW LEVEL SECURITY` and:

- one **restrictive** `app_boundary` policy, `app = sb_ctx_app() AND sb_ctx_admitted()`. Restrictive
  policies are ANDed with everything else, so no sharing policy can widen the app boundary;
- **permissive** per-command policies (`read`, `edit`, `creates`, `purge`, `share`, …) for owner,
  team, app-wide and grant access. Write policies are per command, never `FOR ALL`;
- a `BEFORE UPDATE` trigger that checks the *old* row when visibility, team or `deleted_at` change,
  so sharing and deletion need share and manage rights, not just write.

The context readers (`sb_ctx_app()`, …) raise `42501` when a setting is missing, empty or
malformed. Policies call them as `(SELECT fn())`, which PostgreSQL evaluates once per statement as
an InitPlan; team and grant lookups are inlined set-returning functions, so they use the
`ix_grants_*` and team indexes (`TestPolicyPlansUseIndexes` checks the plans).

The boundary is also structural. Every app-owned table has `app` in its primary or unique keys, and
foreign keys include `app` (`(app, collection) → collections`, `(app, record_id) → records`, …), so
a row in one app cannot reference a row in another. Object keys (`apps/<app_id>/<env>/<blob>/…`),
cursors (bound to app and listing), data-key scopes, AAD and blind-index tokens include the app too.

### Transactions

`store.DB.Run(ctx, scope, fn)` is the only way service code touches the database:

1. `BEGIN`, then one parameterized `SELECT set_config('strongbox.app', $1, true), …` for the scope
   (transaction-local, so a pooled connection never carries context into the next transaction);
2. `fn(tx)`;
3. on error, panic or cancelled context: `ROLLBACK` on a detached context with a 5-second bound;
4. otherwise `COMMIT` on a detached context with a 10-second bound. If the commit outcome is unknown
   (connection lost mid-commit), `Run` returns `ErrCommitUnknown`; operation receipts let the client
   find out what happened.

Modes: `app` (a request), `worker` (background work pinned to one app, no member checks), `global`
(the principal registry and the global audit chain), `dispatcher` (outbox and audit-delivery
bookkeeping, no app data).

## Request path

```mermaid
sequenceDiagram
  participant C as App / agent
  participant API as API (net/http)
  participant S as Service
  participant DB as Postgres (RLS)
  participant K as Cloud KMS
  participant O as Object store

  C->>API: POST /v1/apps/notes/collections/todo/records<br/>Bearer token, Idempotency-Key
  API->>API: verify JWT; load principal; intersect if delegated
  API->>S: Create(ctx{app: notes:prod, subject, actor, op_id})
  S->>DB: BEGIN; set_config(app, subject, actor, mode)
  S->>DB: claim receipt (app, subject, actor, op_id)
  S->>S: policy check (scopes, clearance, marking)
  S->>K: unwrap data key (cache miss only)
  S->>DB: INSERT record (RLS WITH CHECK), revision, index tokens
  S->>DB: complete receipt; append audit event (app chain)
  S->>DB: COMMIT
  API-->>C: 201, ETag, X-Strongbox-Marking
```

Blob bytes go to the object store before the database commit. The row is `pending` with a lease
during the upload; commit is a conditional `pending → active` update by the lease holder. A crash
leaves a `pending` row whose lease expires; the worker aborts it and queues the object for deletion.

## Disclosure rules

- A resource the caller may not see returns `404`, the same as one that does not exist
  (`STRONGBOX_CONCEAL_DENIED_RESOURCES`, on by default). Cross-app IDs return `404`.
- List and query exclusions happen in SQL, before `LIMIT`: RLS removes rows the caller cannot read,
  and the query adds `marking = ANY(allowed)` for markings the caller's clearances admit. Page sizes,
  cursors and ordering therefore say nothing about hidden rows.
- A filter is an assertion about content. Filtered queries consider only records whose content the
  caller may read, so an agent that is denied content cannot use filters as an oracle
  (`TestFiltersAreNotAnOracle`).
- There are no count endpoints and no plaintext search indexes. Equality filters use HMAC
  blind-index tokens (below).
- Errors are sanitized: schema compile errors, for example, never include fetched content.

## Revocation

Every request evaluates membership, team membership, grants and visibility in its own transaction,
so a committed revocation applies to the next statement any request runs. Specifically:

| Situation after revocation | Result |
|---|---|
| New read, list or query | Row is excluded (RLS) |
| Next page of an existing cursor | Row is excluded; the cursor holds only a position |
| Retry of an earlier operation (receipt replay) | Re-authorized; returns `404`/`403` if access is gone. A replay never returns content the caller can no longer read. |
| Blob download already streaming | Completes. Authorization happens before the first byte. |
| Data keys cached in the API | Unaffected (keys are per app, not per user); the cache cannot be used without passing RLS |
| Removing a member | Their owned resources stay owned by them and stay inaccessible to them. An admin moves ownership with `strongbox admin transfer-owner`. |

Principals are read from the database on every request, so disabling a principal or changing a
clearance applies to the next request.

## Encryption contexts

AAD binds each ciphertext to where it belongs. App-bound versions are current; legacy versions stay
readable (`aad_version` column) and are re-sealed on the next write where possible.

| Object | Current AAD | Legacy |
|---|---|---|
| Record | `strongbox/record/v2\|app\|collection\|id\|banner\|version` | `…/record/v1\|collection\|id\|banner\|version` |
| Blob segments / metadata / DEK | `strongbox/{blob,blob-meta,blob-dek}/v3\|app\|id\|banner` | `…/v2\|id\|banner` |
| Data-key wrap (KMS) | `strongbox/datakey/v2\|app\|id\|scope\|purpose` | `…/datakey/v1\|id\|scope\|purpose` |
| Blind-index token | `HMAC(index key, app ␟ collection ␟ field ␟ canonical value)` (v2) | v1 without app |

### Key hierarchy

```
Cloud KMS HSM key "data-kek"     rotates every 90 days; old versions stay enabled for unwrap
 ├── per-blob data key           wrapped with the blob DEK context; one per object
 │     └── object ciphertext     AES-256-GCM, 64 KiB segments, module-generated nonces
 ├── per-app "blobmeta" key      rotates (STRONGBOX_DATA_KEY_ROTATION_SECONDS); seals filename + metadata
 ├── per-app collection key      rotates; seals each record and each revision
 ├── per-app collection index    never rotates; HMAC-SHA-256 blind-index tokens
 └── per-app receipt key         HMAC fingerprints of operation requests
```

Unwrapped keys are cached in a bounded LRU (`internal/cache`) with a TTL; concurrent misses for the
same key share one KMS call. See [OPERATIONS.md](OPERATIONS.md#keys) for rotation and KMS failure.

**Indexes on encrypted data.** Equality search uses deterministic HMAC tokens per (app, collection,
field, value). Someone with database access learns which records share a value and how often, but
not the value. Range and full-text search are not supported on encrypted collections.

### Ciphertext format

Blob objects start with a 10-byte header (`SBX2`, version, algorithm, segment size). Each 64 KiB
plaintext segment becomes `nonce(12) | ciphertext | tag(16)`, sealed with
`cipher.NewGCMWithRandomNonce`, so the FIPS module generates every IV. The AAD is the header, the
object context, the segment index and a final-segment flag, so reordering, truncation, extension and
cross-object swaps all fail. Go's enforced FIPS mode (`GODEBUG=fips140=only`) rejects caller-chosen
GCM IVs, which is why the format does not use a counter nonce. See
[STORED_FORMATS.md](STORED_FORMATS.md) for every format ever written.

## Operations, receipts and retries

Every mutation carries an operation ID (`Idempotency-Key` header; the SDKs generate one per logical
operation and reuse it across retries). The receipt key is `(app, subject, actor, op_id)`, so an
agent acting for a user and the user acting directly never share a namespace.

1. The receipt is claimed (`INSERT … ON CONFLICT DO NOTHING`, then `FOR UPDATE`) **before** version
   preconditions run. A lost response is therefore retried into the same result, not into
   `412 precondition_failed`.
2. The fingerprint is HMAC-SHA-256 under the app's receipt key over operation type, target,
   expected version, marking and payload digest. A retry with a different request gets
   `409 idempotency_key_reused`.
3. The receipt commits with the mutation. A concurrent attempt with the same ID gets
   `409 operation_in_progress` with `Retry-After`.
4. A replay returns the version that operation wrote, re-authorized against current rights.
5. `GET /v1/apps/{app}/operations/{op_id}` reports `pending`, `succeeded` (with resource and
   version) or `not_found`. Receipts expire after seven days.

## Record history and undo

Each write stores the new sealed bytes in `record_revisions` (same key and AAD as the live row at
that version). `GET …/records/{id}/history` lists versions; `POST …/records/{id}/restore` with a
version writes a **new** version whose content is the old one, through the same compare-and-swap,
so undo never rewrites history. The restored marking is `Combine(current, old)`, so undo cannot
lower a classification. Deleted records keep no content in the live row; their revisions remain
until history expiry (`collections.history_limit`, default 100) or a purge.

## Audit

Audit events are appended in the transaction that makes the change, to a per-app hash chain
(`app:<app>:<stripe>`, `STRONGBOX_AUDIT_STRIPES` stripes per app to spread lock contention) or the
global chain for principal changes. The chain head row is locked for the append, so within a chain
sequence order equals commit order. Denials are written after the request's transaction rolls back,
in their own transaction. Each event's hash covers the chain, app, format version and the previous
hash; `strongbox audit-verify [-app …]` checks every chain.

The worker delivers committed events to the structured log (and from there to the locked Cloud
Logging bucket) through a per-chain cursor (`audit_delivery`). Delivery is at least once.

## Outbox and worker

Side effects outside the database (deleting objects today) are written as outbox jobs in the same
transaction as the change. The worker claims jobs with `FOR UPDATE SKIP LOCKED` under a lease,
executes them, and marks them done; failures back off exponentially and become `dead` after
`max_attempts`. Effects are idempotent, so at-least-once execution is safe. Payloads hold IDs only.

The same worker, pinned to one app at a time, aborts expired uploads, trims history and drops
expired receipts. It runs inside `strongbox serve` by default (`-worker=false` to disable) or alone
as `strongbox worker`. Any number can run.

**Towards a change feed.** The outbox is the place a future change feed would read from, but a feed
must not use the outbox `id` (a sequence) as a position. Sequence values are allocated at insert
time and transactions commit in a different order, so a reader that has seen id 42 can later see
id 41 commit. A correct feed needs a commit-ordered position: per-chain sequence numbers assigned
under a row lock (as the audit chains do), or `pg_current_xact_id()` with a snapshot `xmin`
horizon. Realtime delivery, webhooks and CRDT merging are out of scope.

## Failure behavior

| Failure | Behavior |
|---|---|
| Audit append fails | The mutation rolls back (same transaction) |
| Ciphertext fails authentication | `integrity_violation`, audited as `error`; the first segment is checked before the response starts |
| Upload interrupted or crashed | Row stays `pending` until its lease expires; the worker aborts it and deletes the object |
| Stale write | `412 precondition_failed` (If-Match / expected version) |
| Retry after a lost response | Same operation ID returns the original result |
| Commit outcome unknown | `503`, `ErrCommitUnknown`; the client checks the operation ID |
| Statement timeout or pool exhaustion | `503 unavailable` with `Retry-After` |
| KMS unavailable | Requests needing an uncached unwrap fail with `503`; cached keys keep serving until their TTL |
| Request without context reaches the database | `42501`, mapped to `403`; nothing is returned |

## Supabase

Strongbox does not depend on Supabase. Cloud SQL for PostgreSQL and GCS are the primary platform
and BigQuery is the analytics target. Strongbox runs on any PostgreSQL 16 and any S3-compatible
store, so self-hosted Supabase can serve as the substrate, with three rules:

- Strongbox does the encryption, not Vault/pgsodium (libsodium ciphers are not FIPS-approved).
- Nothing but the Strongbox API talks to those tables and buckets. PostgREST, the Storage API and
  Realtime must not expose them: keep the schema out of exposed schemas and revoke
  `anon`/`authenticated`. PostgREST-style direct table access is exactly what "apps must not receive
  database credentials or arbitrary SQL" rules out.
- Hosted Supabase is outside an Assured Workloads boundary; do not use it for CUI.

## Extending

- **Object store:** implement `store.Backend` (`OpenWriter`, `Read`, `Delete`, `Describe`).
- **KMS:** implement `crypto.KeyProvider` (`Wrap`, `Unwrap`, `Describe`) with AAD support.
- **Authorization:** implement `service.Authorizer`. RLS stays the database-side backstop.
- **Identity providers:** `auth.Verifier` is an interface; route on the unverified `iss` claim.
- **Migrations:** add numbered files to `internal/store/migrations/`. `strongbox init` applies
  pending ones in order under an advisory lock, as the migration login. Migrations are additive;
  `serve` refuses to run against a schema older than the build.
