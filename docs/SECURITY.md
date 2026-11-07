# Security and CUI handling

This document explains what Strongbox enforces, how that maps to NIST SP 800-171 (Rev. 2 numbering,
which CMMC Level 2 assesses against), and what remains your responsibility. Strongbox is one component of
a system security plan. It does not make an environment compliant on its own, and nothing here is a
certification.

## Control mapping

| Requirement | How Strongbox addresses it | Your part |
|---|---|---|
| 3.1.1 / 3.1.2 Limit access to authorized users and transactions | OIDC authentication on every call; per-action scopes; deny by default | Register principals; review them |
| 3.1.3 Control the flow of CUI | ABAC on markings (categories, LDCs, NOFORN, export control); agent content withholding; marking roll-up on responses | Approve LLM boundaries; set network egress controls |
| 3.1.4 Separation of duties | Admins cannot edit their own principal; MCP identity has no KMS or data-store access | Assign admin and audit roles to different people |
| 3.1.5 Least privilege | Separate service accounts for API and MCP; KMS key-level IAM; bucket-level IAM | Keep `api_invokers` minimal |
| 3.3.1 / 3.3.2 Audit and attributable actions | Every decision recorded with actor, on-behalf-of, resource, marking, reason; Cloud Audit Logs for KMS, Storage and SQL | Review logs; set retention |
| 3.3.4 Alert on audit failure | Audit writes are fail-closed (request fails) | Alert on 5xx and on `audit-verify` failures |
| 3.3.8 Protect audit information | SHA-256 hash chain with `strongbox audit-verify`; copy in a dedicated log bucket | Lock the log bucket; restrict `audit:read` |
| 3.5.1 / 3.5.2 Identify and authenticate | JWT signature, issuer, audience, expiry and lifetime checks; Google ID tokens for workloads | MFA at the IdP for people |
| 3.8.3 Sanitize media | Crypto-shredding destroys the wrapped data key, making all ciphertext copies unrecoverable | Define when shredding is required |
| 3.8.4 Mark media with CUI markings | Banner stored per object, validated against the Registry format, returned in `X-Strongbox-Marking` | Train users to choose markings |
| 3.13.8 Protect CUI in transit | TLS to Cloud Run; Cloud SQL `ENCRYPTED_ONLY`; HSTS | Internal load balancer and certs |
| 3.13.10 Key management | Cloud KMS HSM keys, automatic rotation, separate app and infra keys, AAD-bound wrapping | Key access reviews |
| 3.13.11 FIPS-validated cryptography | Go FIPS 140-3 module (`GOFIPS140`); AES-256-GCM, HMAC-SHA-256, SHA-256 only; startup refuses to run outside FIPS mode in production; KMS HSM | Confirm the module's CMVP status (below) |
| 3.13.16 Protect CUI at rest | Application envelope encryption plus CMEK on bucket and database | — |

## FIPS-validated cryptography

AES-256-GCM, HMAC-SHA-256 and SHA-256 are approved algorithms, but 3.13.11 requires a **validated module**.
Strongbox uses Go's native FIPS 140-3 module, so no OpenSSL or cgo is involved:

1. The image is built with `GOFIPS140=v1.0.0`, which links the frozen module version the Go project
   submitted (through Geomys) for CMVP validation and turns FIPS mode on by default. Check the CMVP list for that module's
   certificate status before relying on it in your SSP; vendors have also validated rebuilds of it.
2. Every IV is generated inside the module (`cipher.NewGCMWithRandomNonce`). That is required by
   `GODEBUG=fips140=only`, which rejects non-approved algorithms and caller-chosen GCM IVs outright.
   The full test suite, including the API, MCP server and Postgres paths, runs in that mode in CI.
3. With `STRONGBOX_REQUIRE_FIPS=true` (mandatory in production) the process refuses to start unless the
   module is active. `strongbox fips-check` reports the module version and exits non-zero otherwise.

The image sets `GODEBUG=fips140=on`. Switch to `fips140=only` once you've confirmed your GCP endpoints
negotiate FIPS-approved TLS (they normally do). Key wrapping happens inside Cloud KMS HSMs, which are
validated separately.

## Threat model

| Threat | Mitigation |
|---|---|
| Database dump or backup leak | Records, metadata and data keys are sealed or wrapped; indexes are HMAC tokens |
| Bucket misconfiguration | Objects are ciphertext; public access prevention enforced |
| Insider edits a marking in the database to downgrade data | Marking is in the AAD; decryption fails and is audited |
| Ciphertext swapped between rows or objects | Object/record id is in the AAD |
| Rollback of a record to an older ciphertext | Version is in the AAD |
| Truncated, reordered or extended object | Segment index and final-segment flag in each segment's AAD |
| Foreign person probing for ITAR data | Denials are concealed as 404; list and query results are filtered |
| Prompt injection through stored content | MCP tools exclude delete/shred; instructions tell the model to treat content as untrusted; writes are attributable and reversible |
| CUI flowing into an unauthorized model context | Content withheld unless the agent is registered as inside an authorized LLM boundary |
| Compromised MCP server | Holds no KMS, bucket or database permissions; can act only within the intersection of its identity and the user's |
| Forged or replayed tokens | Signature, issuer, audience, expiry, maximum lifetime; short-lived Google ID tokens |
| Audit tampering | Hash chain detects edits, deletions and truncation; independent copy in Cloud Logging |
| Retry storms creating duplicates | Idempotency keys |

**Known limits.** Blind indexes reveal equality and frequency to someone with database access. Plaintext
from non-final segments is released as each segment authenticates, so a consumer that must not act on a
partial object should buffer. The audit hash chain is tamper-evident, not tamper-proof: an attacker with
write access to both the table and the head row could rewrite history, which is why the Cloud Logging copy
exists. Periodically anchoring the chain head with a Cloud KMS asymmetric signature is a good next step.

## Deployment checklist

- [ ] Project inside an Assured Workloads folder for your regime; org policies restrict locations and require CMEK.
- [ ] VPC Service Controls perimeter around KMS, Storage, Cloud SQL, Cloud Run and Artifact Registry.
- [ ] Image built from this repo's Dockerfile (`GOFIPS140=v1.0.0`); `strongbox fips-check` passes in CI.
- [ ] `STRONGBOX_ENV=production` (enforces OIDC, Cloud KMS, Postgres, remote blobs, FIPS, docs off).
- [ ] Container images mirrored into Artifact Registry inside the boundary (including the Cloud SQL proxy).
- [ ] Admin and audit-reader principals assigned to different people.
- [ ] Every agent principal reviewed; `llm_boundary_authorized` set only when its model runs inside the boundary
      (for example open-weight models on GKE in the same folder, or a managed endpoint confirmed in scope for your regime).
- [ ] Log bucket retention set, then locked.
- [ ] Alerts on 5xx rates, `integrity_violation` responses, audit-verify failures and KMS permission errors.
- [ ] Cloud Armor or rate limits in front of the API (auth failures are audited, so floods grow the log).
