# Dreamcatcher workstation checks

Both source ZIPs received HTTP 201 from Dreamcatcher's hosted-app submission endpoint and returned queued build jobs. The [receipts](upload-receipts.json) include the SHA-256 of each submitted ZIP. A separate end-to-end run used the same archive bytes with active fixture releases, the reference server's real context, membership and query checks, and the Strongbox runtime login on PostgreSQL 16. The warehouse adapter returned synthetic rows. Build and deployment attestations in the isolated reference registry came from its test workers. Chromium exercised both uploaded backends behind the local demo edge.

| Check | Observed result |
|---|---|
| Private notebook | Alice's note survived reload and restart. Bob's query returned no private note. The second save with the same operation ID returned the original version. A stale edit received 412. |
| Shared evidence | An entitled member downloaded the same bytes after restart. Substituting a record from another app or another PO line failed. |
| Query and release access | The reference fixture's viewer could use the supplier app but lacked its query permission. The list and download were denied. The local fixture separately demonstrated successful sharing between two entitled members and denied reads after entitlement removal. |
| Identity | A mismatched Strongbox subject was rejected before any storage operation. The synthetic IAM check sent the workload credential only to Strongbox and preserved the end-user credential. |
| Attachment lifecycle | Concurrent link versus shred had one winner. A live link blocked deletion and independent owner transfer at the FK. Detaching, soft delete, undo, clearance, history, revoked grants and receipt replay have executable regression cases. Sealed recovery preserved the link. |
| Validations | 215 top-level Go tests, 226 including subtests, passed in each of two race-enabled FIPS runs. Five live HTTP and six unit tests passed in the TypeScript SDK. The Dreamcatcher runner reported ten passes, including the parent suite for seven end-to-end scenarios and two separate identity checks. No tests skipped. |

[Reference Dreamcatcher snapshot](https://github.com/paulmalmquist/dreamcatcher/tree/50affa57ad3e4119bba5a5300f28fa136716351b) · [combined app and browser run](joined-contract.log) · [Go results](go-tests.tsv) · [TypeScript](typescript-live.log) · [environment](validation.json) · [readiness screenshot](readiness-notes.png) · [supplier screenshot](supplier-evidence.png).

## Resource fairness

With 12 concurrent clients in a noisy app, both quiet apps completed 40 of 40 scheduled requests in the loaded phase. The noisy app received 28,379 throttles and completed 3,774 reads. Each quiet app had a 2-second per-probe budget. This was an eight-second phase on one local server and PostgreSQL process with a two-request, two-connection cap per app. HTTP retries were disabled. Latency percentiles are descriptive for this run. [Full baseline and loaded measurements](fairness.json).

Reproduce with the existing harness on a synthetic deployment. Set `STRONGBOX_MAX_IN_FLIGHT_PER_APP=2` and `STRONGBOX_DB_MAX_CONNS_PER_APP=2` on its API, disable development rate gates to isolate the concurrency cap, then provision with `strongbox-load -setup -users 12`. Run `strongbox-load -fairness-only -users 12 -duration 8s -probe-deadline 2s -out fairness.json` using the matching development signing configuration.

| Severity and guarantee | Finding and reviewed location | Reproduction | Impact and likelihood | Implemented fix |
|---|---|---|---|---|
| Medium · 7 | The PostgreSQL claim subquery could execute repeatedly within a single UPDATE. `internal/service/worker.go:184` at `2e35159`. | `TestOutboxMakesProgressInEveryReadyApp` claimed all 7 eligible jobs with limits of 1 and 2. | One worker can own more leases than it can settle in time, delaying other workers and increasing duplicate work. Reproduced on PG16 with a seven-job queue. | Materialize the selected, locked IDs once, then update exactly those IDs. |
| Medium · 7 | A global FIFO claim spends the whole bounded batch on older jobs from one app. `internal/service/worker.go:187` at `2e35159`. | The same test with just the batch-limit fix left the quiet app's file waiting after two available slots. | File cleanup for another app waits behind an older backlog. A burst of deletions is sufficient. | Rotate across eligible apps, assign each a share, then fill unused slots from the oldest ready jobs. Migration 0013 indexes ready work by app. |

The [failed assertions](worker-red.log) record both stages. The [passing test](worker-green.log) used real object deletion in both apps. Rotation is per running worker and restarts from the beginning after process replacement. This measures queue progress and API admission on the tested topology. Production BigQuery, SSO, Cloud Run autoscaling, Cloud SQL latency and Cloud Storage were outside the run.
