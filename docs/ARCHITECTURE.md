# Architecture

## Principles

1. **One enforcement core.** The REST API and the MCP server both reach data only through the service
   layer (`internal/service`), where every call passes the policy engine and writes an audit event. The MCP
   server is an API client, so it cannot skip either.
2. **Encrypt in the application, not just the platform.** Storage-level CMEK protects disks and backups;
   application-level envelope encryption also protects against database administrators, SQL injection,
   misconfigured bucket ACLs and leaked backups, because none of those paths hold an unwrapped key.
3. **Markings are data with integrity.** A CUI banner travels with every object, is bound into its
   ciphertext, is enforced on every read, and is echoed on every response.
4. **Identity from tokens, clearance from the registry.** Tokens prove who is calling. U.S.-person status,
   CUI categories and dissemination authorizations come from an admin-managed registry and never from
   claims a caller can mint.

## Request path

```mermaid
sequenceDiagram
  participant C as Caller (service or MCP)
  participant API as API route
  participant Auth as authenticate()
  participant G as Guard (policy + audit)
  participant S as Service
  participant K as Cloud KMS
  participant DB as Postgres
  participant O as Object store

  C->>API: Bearer token (+ X-On-Behalf-Of)
  API->>Auth: verify JWT (OIDC/JWKS)
  Auth->>DB: load principal(s); intersect if delegated
  API->>S: operation(ctx, ...)
  S->>DB: load row + marking
  S->>G: evaluate(principal, action, marking)
  G->>DB: append audit event (hash chain)
  alt denied
    G-->>API: 404 (concealed) / 403
  else allowed
    S->>K: unwrap data key (AAD = object id + marking)
    S->>O: stream ciphertext
    S-->>API: plaintext stream + marking
    API-->>C: 200, X-Strongbox-Marking
  end
```

## Key hierarchy

```
Cloud KMS HSM key  "data-kek"   (rotates every 90 days; old versions stay enabled for unwrap)
 ├── blob data keys             one per object, wrapped with AAD "blob-dek|<id>|<marking>"
 │     └── object ciphertext    AES-256-GCM in 64 KiB segments; each segment has a module-generated
 │                              nonce and AAD "blob|<id>|<marking>" + segment index + final flag
 ├── "blobmeta" data keys       rotate weekly; seal filename + metadata per blob
 ├── "collection:<name>" data   rotate weekly; seal each record (AAD binds collection, id, marking, version)
 └── "collection:<name>" index  never rotates; HMAC-SHA-256 blind-index tokens

Cloud KMS HSM key  "infra-cmek"  bucket + Cloud SQL disks (separate key, separate service agents)
```

Data keys for records and metadata are cached in memory for five minutes (configurable), so steady-state
reads cost no KMS calls. Blob reads cost one `Decrypt` per object.

**Crypto-shredding.** `DELETE /v1/blobs/{id}?shred=true` nulls the only copy of the wrapped data key and
deletes the object. Every other copy of that ciphertext (object versions, backups, replicas) becomes
permanently undecryptable, which is how media sanitization works for cloud storage you cannot physically
destroy.

## Data model

| Table | Holds | Sensitive content |
|---|---|---|
| `principals` | identities and clearances | none |
| `data_keys` | wrapped data keys, scope, KEK version | wrapped only |
| `blobs` | marking, type, size, wrapped DEK, sealed metadata, digest, state | sealed only |
| `collections` | name, marking, JSON Schema, indexed fields | schema is not CUI by policy |
| `records` | sealed document (or plain JSON for UNCONTROLLED collections), version | sealed only |
| `record_index` | (collection, field, token, record) | HMAC tokens only |
| `audit_events` / `audit_head` | hash-chained decisions | ids and markings, never content |
| `idempotency_keys` | (principal, key) → resource | request hash only |

**Indexes on encrypted data.** Equality search uses deterministic HMAC tokens per (collection, field,
value). Someone with database access learns which records share a value and how often, but not the value.
Range and full-text search are not supported on encrypted collections; if you need them, keep those fields
in a separate UNCONTROLLED collection or search inside the boundary after decryption.

## Delegation

An agent or service acting for a user sends its own token in `Authorization` and the user's in
`X-On-Behalf-Of`. The caller must hold the `delegate` scope. The effective principal is the intersection
of both: scopes, CUI categories and dissemination controls are intersected, `us_person` and `cui_access`
require both, and `delegate`/`principals:admin` never propagate. Audit events record the agent as `actor`
and the user as `on_behalf_of`. Agents cannot be delegators.

## Ciphertext format

Blob objects start with a 10-byte header (`SBX2`, version, algorithm, segment size). Each 64 KiB plaintext
segment becomes `nonce(12) | ciphertext | tag(16)`, sealed with `cipher.NewGCMWithRandomNonce`, so the FIPS
module generates every IV. The authenticated data is the header, the object context (id and marking), the
segment index and a final-segment flag, so reordering, truncation, extension and cross-object swaps all
fail authentication. Because each object has its own data key, the 2^32 random-nonce limit per key is
never approached (a 5 GiB object is about 82,000 segments).

Go's enforced FIPS mode (`GODEBUG=fips140=only`) rejects GCM with caller-chosen IVs, which is why the
format uses module-generated nonces rather than a counter-derived nonce.

## Failure behavior

| Failure | Behavior |
|---|---|
| Audit write fails | Request fails (fail-closed) |
| Ciphertext fails authentication | `IntegrityViolation`, audited as `error`; first segment is checked before the response starts |
| Upload interrupted | Writer aborted, pending row removed; crash leftovers removed by `strongbox gc` |
| Stale update | `412` (If-Match) |
| Retry after timeout | Same `Idempotency-Key` returns the original resource; a different body with the same key is `409` |
| KMS unavailable | Requests needing a new unwrap fail; cached data keys keep serving records for the cache TTL |

## Supabase

Strongbox needs a Postgres database and an object store, and self-hosted Supabase provides both:

```bash
STRONGBOX_DATABASE_URL=postgres://strongbox@supabase-db:5432/postgres
STRONGBOX_BLOB_BACKEND=s3
STRONGBOX_S3_ENDPOINT_URL=https://<supabase-host>/storage/v1/s3
STRONGBOX_S3_BUCKET=strongbox
```

What Supabase should not do here:

- **Encryption.** Supabase Vault and pgsodium use libsodium ciphers, which are not FIPS-approved, and
  Supabase has marked pgsodium for deprecation. Strongbox's AES-256-GCM + Cloud KMS layer replaces them.
- **Client access.** Supabase's auto-generated APIs (PostgREST, Storage API, Realtime) would let clients
  read Strongbox tables and buckets without policy, markings or audit. Run Strongbox under a dedicated
  database role, keep the tables out of exposed schemas, and revoke `anon`/`authenticated` grants.
- **Hosted projects for CUI.** Hosted Supabase is a commercial SaaS outside an Assured Workloads boundary.

## Extending

- **New backend:** implement `store.Backend` (`OpenWriter`, `Read`, `Delete`, `Describe`).
- **New KMS:** implement `crypto.KeyProvider` (`Wrap`, `Unwrap`, `Describe`) with AAD support.
- **Multiple identity providers:** `auth.Verifier` is an interface; route on the unverified `iss` claim to
  one `OIDCVerifier` per issuer (for example Google for workloads and a workforce IdP for people).
- **Schema migrations:** add numbered files to `internal/store/migrations/`. `strongbox init` applies
  pending ones in order, once, under a Postgres advisory lock.
