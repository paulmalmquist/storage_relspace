# Atomic record saves

`POST /v1/apps/{app}/records/batch` applies 1–25 record commands in **one transaction** with one
Idempotency-Key. The deployment still supplies the environment, and database membership supplies
access. Every operation uses the existing create/update/delete/restore implementation and its
sharing, classification, schema, index, quota, history and audit checks.

```json
{
  "operations": [
    {"type":"update","collection":"tasks","id":"rec_first","expected_version":3,"record":{"data":{"state":"saved"}}},
    {"type":"update","collection":"tasks","id":"rec_second","expected_version":7,"record":{"data":{"state":"saved"}}}
  ]
}
```

For existing records, `expected_version` is mandatory and supplies the per-record compare-and-swap
precondition that a single-record request supplies through If-Match. Create requires `record` and
omits ID/version. Restore additionally supplies `restore_version`. Delete is soft delete. A record
can appear only once. Sharing changes, hard purge, collection changes, cross-app commands and
references to newly generated IDs within the same batch are not supported.

A conflict or validation/authorization/quota/audit failure rolls back **all** writes, revisions,
indexes, counters and success audit events. A failed batch leaves no successful receipt. Denial
audit events follow the existing separate-transaction denial path after rollback.

The response contains IDs, versions and markings, in input order, plus `replayed`. It contains no
record content. Read a record or its pinned revision if the app needs the saved/defaulted payload.
Use the same operation ID when retrying a lost response. Reuse with another payload is rejected.

## Limits and recovery

- One app, at most 25 commands and 1 MiB of input; normal per-record limits also apply.
- Ten-second transaction execution budget, followed by store.DB.Run's bounded commit/rollback
  settlement. Existing request, connection, KMS and per-app pool budgets remain in effect.
- One rate-limit work unit per command; a batch takes one in-flight slot. A configured burst must
  accommodate the batch size. The limits endpoint advertises batch size, bytes and execution budget.
- Transient transaction/deadlock errors retain the existing 503 retry contract. SDK transport
  retries retain the operation ID; batches are never split automatically.
- A receipt stores metadata only. Status and replay recheck **every** affected record under current
  sharing and classification, including the original outcome markings. One inaccessible resource
  makes the whole receipt unavailable; no partial result is returned.
- Migration **11** extends revision retention pins to batch receipts across all actors. Ordinary
  history trimming retains the result versions while their receipts are unexpired. Explicit purge
  and deleted-record expiry still take precedence over recovery.
- Sealed format-2 exports preserve batch receipts, fingerprint keys and history. App renaming remains
  unsupported.

Classification and sharing are checked before row locks, so hidden rows cannot introduce lock
waits before a denial. Collection locks and existing-record locks use a stable order. Normal
command checks run again before each mutation, under the transaction's current RLS decisions.

## Clients

```go
result, err := app.Batch(client.WithOperationID(ctx, "save-related-records-01"), operations)
```

```ts
const result = await app.batch(operations, { operationId: "save-related-records-01" });
```

Both clients generate an ID if omitted and reuse it across transport retries. The MCP server keeps
its existing tools; this change adds no destructive agent tools or management rights.

## Validation

The full integration suite passes with race detection in enforced FIPS mode and again with the
frozen v1.0.0 module: **207 top-level tests, 216 including subtests**, no skipped integration tests.
All **ten** live TypeScript tests, generated types, type checking and the example pass. Vet and
staticcheck pass. Local/fake providers were used; no cloud project or deployment was accessed.

Tests cover all-or-nothing rollback for stale versions, uniqueness, quotas, pending schemas and
audit failure; editor/manager separation; cross-app IDs; one-winner concurrent saves; history pins;
retry/status after access removal; and both SDKs. A lock-holder test first reproduced a hidden CUI
row delaying denial, then passed after authorization moved before locking.

[Summary](evidence/batch/validation.json), [Go results](evidence/batch/go-tests.tsv),
[lock-wait reproduction](evidence/batch/preflight-red.log),
[live TypeScript output](evidence/batch/typescript-live.log).
