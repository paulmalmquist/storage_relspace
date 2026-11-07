# Review findings: reproduction and regression tests

Each finding was first reproduced against `main@8b3af49` with
[`repro_main_8b3af49_test.go.txt`](repro_main_8b3af49_test.go.txt). That file was dropped into
`internal/service/` at that commit and run against PostgreSQL 16. Each reproduction asserts the
correct behavior, so on the old code it fails. The output below is copied from that run. The fixes
landed with the app-scoping work, and every finding has a Go regression test that runs in CI against
PostgreSQL as the restricted runtime role.

| # | Finding | Observed on 8b3af49 | Fix | Regression test |
|---|---|---|---|---|
| 1 | Controlled records in unencrypted collections | `CUI//SP-EXPT record stored in plaintext: {"secret": "engine drawing"}` | The service refuses controlled markings in unencrypted collections on create, update and restore. A database `CHECK (data_plain IS NULL OR marking = 'UNCONTROLLED')` enforces the same rule. `legacy-assign` seals any such legacy rows. | `TestControlledRecordNeverPlaintext`, `TestLegacyAssignment` |
| 2 | Save responses authorized against a stale marking | Code path: `Create`/`Update` re-read the row after commit and authorized it with the marking known before the write, so a concurrent writer's version could be returned. | The response is built from `UPDATE … RETURNING` inside the writing transaction and authorized against that version's marking. | `TestSaveResponseIsTheWrittenVersion` (40 concurrent writers, data and marking checked pairwise) |
| 3 | Stale deletes / update-delete races | `delete with expected version 1 removed the record after it moved past version 1` | Delete is one conditional `UPDATE … WHERE version = $expected AND deleted_at IS NULL`. Index rows are removed in the same transaction. Updates use the same compare-and-swap. | `TestStaleDeleteAndUpdateDeleteRace` (20 update/delete races, exactly one winner, index state checked) |
| 4 | Upload cleanup vs completion race | `commit error: not_found: blob not found; object exists: true; 'blob stored' audit events: 1` | There is an upload state machine with leases. Commit and sweep are both conditional updates on `state = 'pending'` (commit also requires the lease holder; sweep requires an expired lease). The loser deletes its own object and an outbox job is the durable fallback. "Stored" is audited in the commit transaction. | `TestUploadSweepAndCommitRace`, `TestExpiredUploadLeaseIsTakenOver` |
| 5 | Duplicate concurrent uploads | `one idempotency key produced 2 active blobs` | An atomic receipt claim (`INSERT … ON CONFLICT DO NOTHING` plus `FOR UPDATE`) with a lease makes concurrent attempts get `operation_in_progress`. Exactly one blob exists. A retry with different content or metadata gets `idempotency_key_reused`. | `TestConcurrentUploadsWithOneOperationID`, `TestConcurrentPutsConverge` |
| 6 | Lost responses | `retry of a successful update failed: precondition_failed: record is at version 2, not 1` | Every mutation takes an operation ID. Durable receipts commit with the mutation and are resolved before the version precondition. Replays return the exact version written, re-authorized. `GET /operations/{op_id}` reports status. | `TestLostResponseRetries`, `TestLostResponseIsRecovered` (SDK through a dropped 502) |
| 7 | Idempotency scope and fingerprints | `agent acting for the user replayed the user's own operation (shared idempotency namespace)`; request hash was an unkeyed SHA-256 of the payload | The receipt key is (app, subject, actor, op_id). The fingerprint is HMAC-SHA-256 under a per-app, KMS-wrapped receipt key over op type, target, expected version, marking and payload digest. | `TestReceiptNamespaceAndFingerprint` |
| 8 | Mutation/audit gaps | `create error: ERROR: audit sink down; records committed: 1` | Audit events are appended inside the mutation transaction (per-app hash chains). Denials are written after rollback in their own transaction. External delivery reads committed events through a cursor. | `TestMutationAndAuditCommitTogether`, `TestDeliveryIsCursorBased` |
| 9 | Schema loading | An unauthorized caller made the server read `/etc/hostname`: `failing loading "file:///etc/hostname": invalid character 'v'…` (the error also leaked the file's first byte) | Authorize before compiling. A loader refuses every external `$ref`. Size, depth and node limits apply. Errors are sanitized. | `TestSchemaLoadingIsAuthorizedAndClosed` |
| 10 | Retention claims | Docs claimed crypto-shredding made data unrecoverable everywhere. | The claim is replaced in [RETENTION.md](../RETENTION.md), which separates delete, purge, shred, history expiry and backup expiry. | (documentation) |

## Raw output (8b3af49)

```text
=== RUN   TestRepro1ControlledRecordInUnencryptedCollection
    repro_test.go:33: CUI//SP-EXPT record stored in plaintext: {"secret": "engine drawing"}
--- FAIL: TestRepro1ControlledRecordInUnencryptedCollection (2.13s)
=== RUN   TestRepro3StaleDeleteRace
    repro_test.go:55: delete with expected version 1 removed the record after it moved past version 1
--- FAIL: TestRepro3StaleDeleteRace (0.04s)
=== RUN   TestRepro4SweepVersusCommit
    repro_test.go:75: commit error: not_found: blob not found; object exists: true; 'blob stored' audit events: 1
    repro_test.go:77: sweep/commit race left an orphaned object or recorded a store that did not happen
--- FAIL: TestRepro4SweepVersusCommit (0.04s)
=== RUN   TestRepro5DuplicateConcurrentUploads
    repro_test.go:97: one idempotency key produced 2 active blobs (false vs 2)
--- FAIL: TestRepro5DuplicateConcurrentUploads (0.04s)
=== RUN   TestRepro6LostUpdateResponse
    repro_test.go:112: retry of a successful update failed: precondition_failed: record is at version 2, not 1
--- FAIL: TestRepro6LostUpdateResponse (0.04s)
=== RUN   TestRepro7IdempotencyNamespace
    repro_test.go:129: agent acting for the user replayed the user's own operation (shared idempotency namespace)
--- FAIL: TestRepro7IdempotencyNamespace (0.04s)
=== RUN   TestRepro8MutationWithoutAudit
    repro_test.go:150: create error: ERROR: audit sink down (SQLSTATE P0001); records committed: 1
    repro_test.go:152: record committed although its audit event could not be written
--- FAIL: TestRepro8MutationWithoutAudit (0.04s)
=== RUN   TestRepro9SchemaLoading
    repro_test.go:162: unauthorized create with a file reference: validation_failed: invalid JSON Schema: failing loading "file:///etc/hostname": invalid character 'v' looking for beginning of value
    repro_test.go:163: want forbidden, got validation_failed: invalid JSON Schema: failing loading "file:///etc/hostname": invalid character 'v' looking for beginning of value
--- FAIL: TestRepro9SchemaLoading (0.04s)
```

Finding 2 was not given a runtime reproduction on the old code. Its failure window lies between two
statements in one request, and the old code had no hook to hold it open, so it is shown from the code
path above. The regression test exercises the fixed path under real concurrency.
