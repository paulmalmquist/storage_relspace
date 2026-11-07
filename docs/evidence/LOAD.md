# Synthetic load results (2026-11-07)

**Synthetic.** These numbers come from one 2-CPU, 7 GB container running the load generator, one
`strongbox serve` process and PostgreSQL 16 (default settings: `shared_buffers` 128 MB,
`max_connections` 100) side by side, with local keys and local blob storage. Client and server
compete for the same two CPUs. They show how the service behaves under contention and overload.
They are not an estimate of production capacity, which depends on Cloud SQL tier, Cloud Run
instance count and size, KMS latency and GCS, none of which were involved.

Server configuration: defaults (`STRONGBOX_DB_MAX_CONNS` 10, per-app share 5, rate limits 50/s
per subject and 500/s per app, 64 requests in flight per app), restricted runtime login, every
record in a `CUI//SP-EXPT` collection (encrypted), every blob encrypted.

Run it: `strongbox-load -setup` (with the server's `STRONGBOX_*` configuration), then
`strongbox-load -url http://… -users 32 -duration 15s -step 10s -sweep 50,100,200,400,800 -out results.json`.
Raw output: [load-synthetic-2026-11-07.json](load-synthetic-2026-11-07.json).

## Closed-loop workloads (32 users, 15 s each)

| Workload | What each user does | ops/s | p50 | p95 | p99 | Final-state check |
|---|---|---|---|---|---|---|
| private-state | read-modify-write of their own record (CAS) | 196 | 159 ms | 192 ms | 225 ms | ok: every record's version and counter equal its owner's successful updates |
| shared-record | read, then CAS-increment one shared record | 281 | 97 ms | 128 ms | 1060 ms | ok: counter (309) equals successful increments; 3908 writes lost the race and got 412, none was lost |
| blobs | upload 64 KiB, read it back | 138 | 234 ms | 286 ms | 312 ms | ok: all 2075 blobs re-read intact afterwards |
| quiet-alone | 4 users read their own record | 222 | 4.2 ms | 8.4 ms | 1005 ms | — |
| quiet-beside-noisy | the same, while 96 writers flood another app | 213 | 11 ms | 25 ms | 44 ms | — |

The final-state checks read back through fresh clients after each workload, independently of the
counts the workload kept.

The p99 near 1 s on quiet-alone and shared-record is the per-subject rate limit at work: four
users reading as fast as possible exceed 50 requests/s each, get `429` with `Retry-After: 1`, and
the SDK waits and retries. Errors are not counted because the retries succeeded; the latency is.

**Noisy neighbour.** The first run of this harness, before the per-app connection share existed,
measured quiet-beside-noisy at 12.6 ops/s with p50 305 ms: the noisy app's 64 in-flight requests
queued for all ten pool connections and the quiet app waited behind them. Each app is now limited
to half the pool (`STRONGBOX_DB_MAX_CONNS_PER_APP`), and the quiet app kept 96% of its throughput
with p95 25 ms while the noisy app was throttled (`429` from its in-flight cap).

## Open-loop sweep (fixed arrival rate, 10 s per step)

Requests are issued on schedule whether or not earlier ones finished; latency is measured from the
scheduled start, so queueing and client retries appear as latency rather than as reduced load. Each
request creates one record.

| Offered | Achieved | p50 | p95 | p99 | Errors | Final-state check |
|---|---|---|---|---|---|---|
| 50/s | 50/s | 9.0 ms | 13 ms | 40 ms | none | ok: 500 records = successful creates |
| 100/s | 100/s | 8.0 ms | 9.6 ms | 12 ms | none | ok: 1000 |
| 200/s | 200/s | 8.3 ms | 20 ms | 44 ms | none | ok: 2000 |
| 400/s | 285/s | 3.3 s | 4.4 s | 4.5 s | 1323 × `429` | ok: 2677 |
| 800/s | 562/s | 4.1 s | 4.4 s | 4.6 s | 5578 × `429` | ok: 2422 |

On this host the knee is between 200 and 400 creates/s. Past it, the per-app in-flight cap sheds
load with `429` instead of letting queues grow without bound, latency is dominated by SDK retries,
and every create that reported success is present (none lost, none duplicated).
