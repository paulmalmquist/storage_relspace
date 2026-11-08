# Strongbox Medium follow-up

Scope: the twelve Medium findings left open after the review of `2e35159`, continuing from
`6d5edab`. All twelve original reproductions now pass and run without a build tag. Six High fixes
from the earlier review remain in place. This closes the reproduced defects; it does not establish
all production guarantees for every workload or a deployed cloud configuration.

## Changes

Original failing tests and base file:line references remain in
[the initial review](STRONGBOX_REVIEW_2e35159.md). The fixes are deliberately narrow; M10 closes by
refusing an unsupported export, rather than introducing a new encryption format in this patch.

| Finding | Result and implementation | Regression evidence |
|---|---|---|
| M01 Save protections | HTTP app mutations require operation IDs; record DELETE requires If-Match. Blob delete, sharing, team/member changes, upload parts/abort and migration cancellation now claim/complete receipts. SDK transport retries retain one ID. Multipart SDK helpers derive distinct session/part/complete IDs. | `TestReviewMutationsRequireOperationID`, `TestReviewDeleteRequiresIfMatch`, `TestReviewBlobDeleteUsesReceipt`, `TestReviewSharingReceiptDoesNotRepeatAnOldChange`, `TestReviewPartReceiptSurvivesCompletionAndRejectsChangedBody`; SDK/live tests |
| M02 Sharing policies | Migration 8 provides a scoped, narrow visibility command and share-bit helper; grant UPDATE validates old/new authority. General content UPDATE remains restricted. Upserts return the actual original grant creator. | `TestReviewShareOnlyGranteeCanChangeVisibility` also checks denied edits/delegation; `TestReviewExistingGrantCanBeChanged`; existing runtime sharing tests |
| M03 Compatibility | Normalize JSON inputs; distinguish absent const from null. Changed schema objects with unanalysed validation keywords or changed dialects stage a migration. | `TestReviewWideningProofRejectsTightening`; existing compatible-change, staged-writer and migration tests |
| M04 Stable replay | Singleton creation locks only on a cache/database miss; SQL constrains active receipt/index keys. Replay fingerprints use stored key IDs. Unexpired receipts pin revisions across ordinary trimming; absent history returns result_expired instead of newer data. | `TestReviewConcurrentFirstReceiptsRemainReplayable`, `TestReviewTrimmedReceiptNeverReturnsDifferentVersion`, `TestReviewReceiptUsesRetiredFingerprintKey` |
| M05 Private metadata | Usage counts RLS-visible, classification-readable resources and labels the result `scope: visible`. Migration details require app admin, apps:operate and clearance for every collection marking. Cancellation redacts progress/failure details. | `TestReviewUsageDoesNotCountHiddenResources`, `TestReviewMigrationDoesNotDisclosePrivateRecordIDs`; SDK tests verify ordinary writer denied and operator allowed |
| M06 Session revocation | Session metadata now evaluates current BlobReadMeta policy, including replay/status paths. | `TestReviewUploadStatusRechecksClearance` |
| M07 Runtime role | Reject extra direct/transitive memberships, object ownership beyond tables, and direct login ACL grants in user schemas. | `TestReviewRuntimeCheckRejectsExtraReadAllRole`, `TestReviewRuntimeRejectsDirectGrantsAndFunctionOwnership` |
| M08 Authentication budgets | Deadline begins before authentication. A bounded authentication gate precedes app budgets. Registry access uses DB.Run; registry work inside transactions reuses them. Timeouts map to 503. Streams have a separate configurable deadline, including transport reads/writes. | `TestReviewDeadlineStartsBeforeAuthentication`, `TestReviewPrincipalLookupUsesAcquisitionBudget`; existing API/pool tests |
| M09 Quota batches | Migration 9 reserves a configured record quota row before positive shard changes. Under the service's READ COMMITTED transactions, batch admission is exact; unlimited apps avoid that lock. | `TestReviewRecordQuotaOvershootIsAtMostSeven`; existing quota/usage tests |
| M10 Plaintext export | Format 1 refuses apps containing plaintext record payloads/revisions before creating any files. Encrypted UNCONTROLLED collections remain supported. Metadata remains readable. | `TestReviewExportContainsNoPlaintextRecordData` checks the refusal and empty output directory; encrypted round-trip tests |
| M11 Multipart recovery | Export includes acknowledged pending parts and refuses missing required files. Offline validation checks complete active inventories, part numbers/sizes, ciphertext bytes and ordered digests. Reads and deep verify share one list validator; deep verify also checks plaintext size. Part replacement serializes even before a part row exists. | `TestReviewOfflineValidationRequiresCompletePartList`, `TestReviewDeepVerifyChecksMultipartDigestList`, `TestReviewPendingSessionRestoreKeepsAcknowledgedParts`; existing upload races/integrity tests |
| M12 Source database | Compare cluster identity plus database independently of schema; identity failures stop recovery. Successful restore tests now create genuinely separate databases. | `TestReviewRestoreRefusesSameDatabaseAcrossSchemas`, `TestExportValidateRestore`; shared-target principal and malformed-input tests |

## Validation

Go 1.26.10, PostgreSQL 16.15 and Node 22.18.0; synthetic local data only. No deployment or cloud
project was accessed.

- `STRONGBOX_TEST_DATABASE_URL=… STRONGBOX_REQUIRE_INTEGRATION=1 GODEBUG=fips140=only go test -race -count=1 ./...`: 173 top-level tests, 175 including subtests; zero skipped tests or failures.
- The same full suite with `GOFIPS140=v1.0.0`: identical pass count.
- TypeScript generated types match OpenAPI; typecheck passes. All nine tests pass against the throwaway server, and the demo completes.
- Go vet and staticcheck pass. Govulncheck reports no affected callable symbols; it identifies one advisory in a required module whose vulnerable code is not called.
- The synthetic four-user load smoke preserves private saves, the shared counter, blob contents and create counts. A quiet app continues making progress beside a busy app. Three-second workloads and local keys/storage do not measure production capacity.

[Validation summary](evidence/review-medium/validation.json),
[every Go result](evidence/review-medium/go-tests.tsv),
[live client output](evidence/review-medium/typescript-live.log),
[load output](evidence/review-medium/load-smoke.log),
[load measurements](evidence/review-medium/load-smoke.json).

## Upgrade and compatibility

Apply migrations 7–9 with the migration identity before running this build. Migration 7 can retire
competing receipt keys safely because receipts retain their key IDs. It stops on competing active
blind-index keys: an operator must inspect references and repair/reindex affected data before
retiring a used key. Silently choosing a key could make old tokens unsearchable or undermine uniqueness.

All HTTP app mutations now need Idempotency-Key, and record deletion needs If-Match. Updated SDKs
supply IDs; custom callers must change. The app usage response now means caller-visible usage.
Detailed migration polling needs the new explicit operational capability. The operator CLI still
provides privileged full usage. Recovery requires stable database identity from pg_control_system();
grant that to the recovery operator as needed, never to the API login. Format 1 cannot back up
plaintext-bearing collections; select encrypted=true for new UNCONTROLLED collections requiring
this export path. No automatic conversion of existing plaintext collections is included.

Global principal configuration and offline administrative commands remain outside the per-app
operation-receipt protocol. Already-authorized streams can finish until their deadline; revocation
applies to the next request. Explicit purge/deleted-record expiry can still remove receipted data.

## What should be added next

These are product/reliability additions, not extra confirmed vulnerabilities. Build in this order:

| Priority | Addition | Why it belongs here | Acceptance criterion |
|---|---|---|---|
| First | Complete encrypted recovery | The safe M10 fix currently refuses plaintext-bearing apps. Format 2 should seal all table payloads with a KMS-wrapped export key and app/export/file AAD. Keep offline digest validation separate from authenticated restore validation. | Plain and encrypted collections both round-trip; no record/index plaintext in bundles; malformed, truncated or rehashed substituted ciphertext is refused before target changes. |
| First | Reconciliation plus recovery drills | Unknown commits and failed restores can leave ciphertext orphans; Backend has no inventory/reconciliation interface. SQL snapshots do not pin external object generations. Existing CLI verification is useful, but an exercised recovery procedure is the deliverable. | Detect missing references, orphan generations, expired reservations, counter drift and stuck/dead outbox jobs. Repairs default to dry run and respect grace periods. Restore into a disposable database, recover keys, deep-verify, and record measured RPO/RTO. |
| Next | Bounded atomic multi-record saves | The HTTP API currently saves one record per mutation. Apps otherwise implement their own partial-save compensation for related state. | One app, fixed operation/byte/time limits, per-record CAS, one receipt and one transaction; any conflict/authorization/schema/quota failure rolls back the whole batch. Replays recheck every affected resource. |
| Next | Attachment references with explicit lifecycle/access rules | Records and blobs are independent; passing a blob ID in JSON creates no enforced relationship. Sharing or deleting a record does not automatically coordinate its attachments. | Scoped foreign-key-backed links; define whether effective access requires both link/record and blob permission. Markings cannot be lowered through a link; deleting shared attachments cannot break another live reference. |
| Next | An application contract and operational view | App provisioning, membership, quotas, suspension, inventory and worker controls already exist as CLI operations. App owners need a coherent onboarding/offboarding path and recovery expectations. | Named owner, default encryption, retention, allowed classifications, quotas, restore objectives and client compatibility recorded per app. Operational details require explicit capabilities; metrics retain bounded labels. |
| Before broad scaling | Fleet and client conformance tests | Current rate/in-flight budgets and pool shares are process-local. Marking/usage scans and worker scheduling need evidence at large app and marking counts. Two live SDK suites establish today's flows, not future compatibility. | Test multiple API/worker replicas with a noisy app, slow KMS, large catalogs and expiring leases. Measure queue age, memory, connection wait and quiet-app latency. Run one adversarial save/replay/revocation/restore contract against each supported SDK version. |

For recovery, pair app exports with Cloud SQL backups/PITR and key-retention policy; these recover
different layers. Cloud SQL documents instance backup and PITR recovery, while Cloud Storage's
generation preconditions prevent delayed retries from acting on a replacement object. KMS rotation
does not re-encrypt old ciphertext, so a successful restore drill must include older key versions:
[Cloud SQL recovery](https://docs.cloud.google.com/sql/docs/postgres/backup-recovery/restore),
[object preconditions](https://docs.cloud.google.com/storage/docs/request-preconditions),
[KMS re-encryption](https://docs.cloud.google.com/kms/docs/re-encrypt-data).

The smallest useful next delivery is **complete encrypted backup plus reconciliation and a measured
restore drill**. Then add bounded transactions and attachment references when a concrete Dreamcatcher
app needs them. Keep arbitrary SQL, search engines and domain workflows outside this storage API.
