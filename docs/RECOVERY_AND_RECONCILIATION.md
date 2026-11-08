# Encrypted recovery and scoped reconciliation

This extends the review branch after `e9aca12`. The new commands use the privileged recovery
identity. Applications and agents keep using the HTTP API and receive no database, key or bucket
credentials. No cloud deployment or cloud recovery was performed for this change.

## Delivered

| Capability | Behavior | Main checks |
|---|---|---|
| Complete encrypted exports | CLI exports format 2. Every table stream is encrypted, including plaintext collections, indexes, principal policy and schemas. Existing encrypted blob files are copied byte for byte. Receipts and unfinished outbox work survive recovery. | `TestSealedExportRecoversPlainCollectionsWithoutPlaintextFiles`, `TestSealedExportDoesNotExposeRegistryOrSchema`, `TestSealedRecoveryPreservesReceiptsAndPendingOutsideEffects` |
| Authenticated restore | A KMS-wrapped export key authenticates the manifest. Per-table stream keys and AAD bind each file to its app, export and filename. Restore validates decrypted scopes, columns and references before target changes. | `TestSealedRestoreRejectsRehashedTamperingBeforeWrites`, `TestRestoreRejectsUnexpectedColumnsAfterFirstRow`, `TestManifestAuthPreservesUnknownSignedFieldsAndRejectsDuplicates` |
| Independent recovery target | Refuses the source database, existing target app, and matching/overlapping declared object namespaces. Local directory aliases are resolved. | `TestSealedRestoreRefusesSourceObjectNamespaceAndSymlinkAliases`, existing source/refused-restore tests |
| Scoped reconciliation | Reports missing/incorrectly sized referenced objects, old unreferenced generations, reservation drift, expired uploads and dead/stale jobs. Scans resume with app-bound cursors, at most 200 references/objects per page. | `TestReconcileMissingFilesAndCursorScope`, `TestReconcileDryRunAndQueuedGenerationCleanup` |
| Safe cleanup | Dry run by default. Apply records an audit event and generation-specific outbox job together. The worker rechecks references, pending uploads, age and current generation. GCS deletion pins generation and metageneration; Unix local storage coordinates mutations across processes. | `TestReconcileProtectsPendingUploadsAndChangedGenerations`, `TestReconcileWorkerRechecksReferencesAndScope`, `TestGCSInventoryConditionalDeletePinsBothGenerations`, local inventory tests |
| Measured restore drill | Runs dry run, restore, deep decryption, usage recount and audit verification in a separate target. Reports phase durations, input snapshot age and failures. Tests repeat the drill in fresh databases and resume an acknowledged pending upload. | `TestRecoveryDrillRestoresMixedDataAndOlderKeys`, `TestRecoveryCommandsUseSealedExportsAndDryRunReconciliation` |

## Commands

Use source configuration for export. Format 2 requires a KMS/keyring provider even when all source
collections already use encryption. Export needs permission to wrap an export key, not to decrypt
existing record/blob payloads.

```bash
strongbox export -app notes:prod -out /secure/notes-export
strongbox validate-export -in /secure/notes-export
strongbox validate-export -in /secure/notes-export -authenticate
```

The first validator is offline and reports `level: transport`, `authenticated: false`: it checks
stored digests, sizes, table inventory and object inventory. It cannot establish authenticity or
inspect encrypted row semantics. `-authenticate` also opens the manifest and every table, validates
row scopes and multipart completeness, and reports `level: authenticated`. It needs keys but no
database; a local keyring works fully offline, while Cloud KMS needs its service.

Configure a separate target database and independent object directory or bucket/prefix, using the
same app identity and access to the required old KMS versions. Initialize it with this build:

```bash
strongbox init
strongbox restore -in /secure/notes-export -dry-run
strongbox restore -in /secure/notes-export -deep
strongbox restore-drill -in /secure/notes-export -timeout 30m
```

Choose **restore or restore-drill** for a fresh target. A drill itself restores the app, so it will
refuse a target into which the earlier restore command already committed. It never drops or
replaces an existing app/database. Run repeated drills against newly provisioned targets.

The drill's `phase_seconds` measures the recovery phases after target initialization; it excludes
infrastructure provisioning. `snapshot_age_seconds` is the age of this bundle's SQL snapshot,
not a production RPO guarantee. Deep checks cover live records, non-delete record revisions and
active attachment content. Pending acknowledged parts are structurally/digest checked and tested
for successful completion after recovery; purged/shredded data cannot be decrypted.

For an existing app, start with a report:

```bash
strongbox reconcile -app notes:prod
strongbox reconcile -app notes:prod -cursor '<next_cursor>'
strongbox reconcile -app notes:prod -apply
strongbox reconcile -app notes:prod -apply -fix-counters
```

Each invocation scans one page; continue until `next_cursor` is absent. Counts describe that page.
Pass `-apply` again on subsequent pages when applying cleanup. Counter recount/repair occurs on
the first page only; `-fix-counters` requires `-apply` and cannot be combined with a cursor.
The overall command timeout defaults to five minutes and object calls to the request-timeout
configuration. The worker processes queued cleanup with its own bounded object-call deadline.

Orphan grace defaults to 24 hours and cannot be shortened below that. Every pending upload's
attempts are protected, including expired leases awaiting the worker. Committed references are
protected even when private. Apply queues work; it does not delete files directly. A changed
object generation or a newly visible reference vetoes a stale cleanup job. The algorithm relies
on the service's existing rule that each upload attempt writes a fresh immutable object key;
it is not a general collector for applications that reuse storage keys outside Strongbox.

## Format 2

- One REPEATABLE READ SQL snapshot supplies all tables. `snapshot_at` records transaction time.
- One fresh export key is wrapped by the configured provider under JSON-array AAD
  `["strongbox/export/v2", app, export_id, "key"]`.
- Each `tables/<name>.ndjson.sbx` has a fresh stream key, sealed by the export key under the same
  context with purpose `file-key/<filename>`. Table streams reuse the existing SBX2 AES-256-GCM
  segmented format with 64 KiB chunks and purpose `<filename>`. No plaintext staging files exist.
- Manifest authentication seals an empty payload under the export key. AAD is the manifest context
  (purpose `manifest`), a newline and the compact canonical JSON document with `encryption.auth`
  set to null. Canonicalization sorts object keys through Go encoding/json, preserves JSON numbers
  exactly with UseNumber, and rejects duplicate keys and nesting beyond 64 levels. Authentication
  retains unknown signed fields so adding optional reader fields does not invalidate old bundles.
- The manifest binds table digests, row/byte counts, sealed stream keys, source identity and the
  object-inventory digest. Object hashes are checked again while copying, before committing writers.
- Manifest and object inventory expose operational metadata such as app, paths, counts, sizes and
  key identifiers. Protect the whole bundle according to its classification.
- Outbox identities are regenerated on the target to avoid collisions in shared databases. Leased
  jobs restart pending; dead jobs remain dead. Durable receipts keep their original app/subject/
  actor/operation namespace and stored fingerprint key. Delivery cursors are rebuilt rather than
  copied, so delivery remains at least once.

Format 1 remains readable. CLI restore requires explicit `-allow-legacy` because that format has no
manifest authentication or source object-namespace identity; the operator must ensure independent
storage. The internal compatibility writer still refuses plaintext-bearing format-1 exports.

## Additional reproduced correctness fixes

Two existing operator usage defects were reproduced before fixing them:

| Defect | Before | Fix and test |
|---|---|---|
| Reservations omitted from drift checks | A pending upload with corrupted reservation bytes/count was reported as having no drift. | Compare/recount both fields; `TestUsageRecountIncludesReservations`. |
| Repair used totals read before locking | A blob committed between the scan and repair; the repair then wrote old totals back. | Lock that app's blob counter and all eight record-counter shards before scanning; update locked shards in place. `TestUsageRepairLocksBeforeTakingItsSnapshot` also proves another app can save during the repair. |

Local writers also use atomic link-not-replace publication, so two writers that opened the same
name cannot overwrite the first committed object. Invalid one-character legacy local keys return
an error instead of causing a slice panic.

## Deployment and limits

Apply migration **10** before using reconciliation, then update workers before queuing the new job
kind. Existing migrations 7–9 remain required. The recovery identity needs scoped database owner
access, KMS permissions for the operation, and bucket read/list/create access as appropriate;
workers need conditional-delete access. The ordinary migration identity need not gain KMS rights.
Standalone KMS factory calls enforce configured FIPS requirements, as API-container creation does.

Reconciliation inventory and conditional cleanup support GCS and Unix local storage. S3 reports
unsupported maintenance capability and retains its existing request/export interfaces. Bucket
historical versions, soft-deleted objects, unfinished temporary files and unscoped legacy orphans
are outside this collector. Storage-prefix identity checks cannot discover aliases between unrelated
provider endpoints. SQL snapshots do not pin external object generations: export fails if a required
object disappears during the copy. Missing live objects are reported, never automatically fabricated.

The next product work remains bounded multi-record saves, explicit attachment links/lifecycles,
application operating contracts, and fleet-scale fairness testing.

Google Cloud references: [generation preconditions](https://docs.cloud.google.com/storage/docs/request-preconditions),
[Go storage APIs](https://pkg.go.dev/cloud.google.com/go/storage). Tests use local/fake providers;
they do not attest deployed IAM, retention or cloud restore performance.

## Validation evidence

Both full integration runs pass with the race detector: **194 top-level Go tests, 203 including
subtests**, in enforced FIPS mode and with the frozen `GOFIPS140=v1.0.0` module. All nine live
TypeScript tests, generated types, type checking and the example pass. No integration tests were skipped.

[Summary](evidence/recovery/validation.json), [every Go result](evidence/recovery/go-tests.tsv),
[two measured synthetic drills](evidence/recovery/drill-reports.json),
[original sealed-export failures](evidence/recovery/sealed-red.log),
[original counter failures](evidence/recovery/counter-red-final.log),
[counter/reconciliation regression run](evidence/recovery/counter-and-reconcile-green.log),
[live SDK run](evidence/recovery/typescript-live.log).

The counter red run applies the corrected test fixture to the pre-fix usage implementation in
an isolated worktree. The final regression also asserts that a second app continues saving.
