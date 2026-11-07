# Upstream references

Projects reviewed while designing app isolation, transactional side effects, authorization and the
TypeScript SDK. "Reviewed" is the commit at the head of the default branch, or the released version,
when the review was done (2026-11-06). Nothing below is vendored or copied. Strongbox adopts patterns
and, where noted, depends on the package as a normal module. No notices are required beyond each
dependency's own license file, which ships with the module.

| Project | Reviewed | License | Adopted | Why |
|---|---|---|---|---|
| [PostgREST](https://github.com/PostgREST/postgrest), [transactions](https://docs.postgrest.org/en/stable/references/transactions.html) | `912ec8744e9f` | MIT | Pattern only. Each request runs in one transaction. Identity is passed as transaction-local settings (`set_config(name, value, true)`) that policies read with `current_setting(name, true)`. Settings read as `''` after commit, so the reader must treat empty as unset. | Same shape as `store.WithApp`. Strongbox does not expose PostgREST or any SQL/RPC surface to apps. |
| [PostgreSQL 16 RLS](https://www.postgresql.org/docs/16/ddl-rowsecurity.html), [CREATE POLICY](https://www.postgresql.org/docs/16/sql-createpolicy.html) | PostgreSQL 16 docs | PostgreSQL License | Policies are combined so that at least one permissive policy and every restrictive policy must pass. `FORCE ROW LEVEL SECURITY` applies policies to the table owner. `UPDATE` also needs `SELECT` visibility. Unique and foreign-key checks bypass policies, which is a disclosure channel. | The app boundary is a `RESTRICTIVE` policy, so permissive sharing policies cannot widen it. Unique-violation disclosure is handled in the collection contract ([ARCHITECTURE.md](ARCHITECTURE.md#disclosure-rules)). |
| [River](https://github.com/riverqueue/river), [transactional enqueueing](https://riverqueue.com/docs/transactional-enqueueing) | `6a1d035f0473` / v0.51.1 | MPL-2.0 (River Pro is a separate paid product) | Pattern only. Jobs are inserted in the same transaction as the data they describe. Workers fetch with `FOR UPDATE SKIP LOCKED`, take a lease, retry with backoff, and discard after a bounded number of attempts. Stuck leases are rescued after expiry. | Not adopted as a dependency. River brings its own migration system and tables outside the app RLS model, and Strongbox needs four job kinds. A ~300-line outbox in the existing migration stream keeps one schema owner, one grant model and per-app job scoping. Nothing mandatory depends on River Pro. |
| [Watermill](https://github.com/ThreeDotsLabs/watermill) [Forwarder](https://watermill.io/advanced/forwarder/), [watermill-sql](https://github.com/ThreeDotsLabs/watermill-sql) | `1911646d2795` / v1.5.3, watermill-sql v4.1.5 | MIT | Pattern only. Events are written to a SQL table inside the business transaction, and a forwarder relays them to the real destination afterwards. | Used for audit delivery to Cloud Logging. Delivery is at-least-once from committed rows, never from inside the request. |
| [OpenFGA](https://github.com/openfga/openfga) | `4b09dafb027d` / v1.22.1 | Apache-2.0 | Not deployed. The `authz.Authorizer` interface is relation-shaped (owner, editor, viewer, sharer over subjects and teams), so an OpenFGA or SpiceDB backend could implement it. | Spec requires these stay optional. RLS stays mandatory whichever authorizer is used. |
| [SpiceDB](https://github.com/authzed/spicedb) | `4613dae441eb` / v1.57.0 | Apache-2.0 | Not deployed (same as OpenFGA). | |
| [openapi-typescript](https://github.com/openapi-ts/openapi-typescript) | `d46a319ae2ef` / openapi-typescript 7.13.0 | MIT | Dev dependency of `clients/typescript`. It generates `src/schema.d.ts` from `internal/api/openapi.json`. | The TypeScript SDK's wire types come from the same contract the Go server is tested against. |
| [testcontainers-go](https://github.com/testcontainers/testcontainers-go) | `6b6d4536b57b` / v0.45.0 | MIT | Not adopted. | CI already runs PostgreSQL as a service container, and local runs use any reachable PostgreSQL. With `STRONGBOX_REQUIRE_INTEGRATION=1`, a missing database fails the run rather than skipping it. |
| [opentelemetry-go](https://github.com/open-telemetry/opentelemetry-go) | `1bf83efa9a01` / v1.47.0 | Apache-2.0 | Dependency: metrics API, SDK and OTLP/HTTP exporter. | Vendor-neutral metrics that the Cloud Run OpenTelemetry sidecar or a collector can receive. It is pure Go with no cgo, so it is unaffected by `GOFIPS140`. |

## FIPS and licensing checks

- Every Go dependency added here is pure Go and uses the standard library's `crypto/tls` for transport.
  The full test suite runs under `GODEBUG=fips140=only` in CI.
- No mandatory behavior depends on a paid extension or product, including River Pro, Supabase
  extensions and PostgreSQL extensions. The schema uses core PostgreSQL 16 only.
