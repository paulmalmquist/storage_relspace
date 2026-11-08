# Stored formats and legacy compatibility

This is the inventory of every persistent format Strongbox has written, which code reads it today,
and what happens to formats that are no longer supported. Readers are Go only. No Python is needed
to read, convert or verify anything.

## Inventory

| Format | Written by | Read by Go today | Notes |
|---|---|---|---|
| Blob stream `SBX2` (10-byte header, random-nonce segments) | Go, all versions | Yes | `internal/crypto/envelope.go`. Segment AAD binds header, context, index and final flag. |
| Blob stream `SBX1` (17-byte header, nonce = prefix‖counter‖last) | Retired Python implementation | **No. Fails with a typed integrity error** naming `SBX1` | Go's `GODEBUG=fips140=only` mode rejects caller-chosen GCM nonces, so SBX1 cannot be opened without weakening FIPS enforcement. |
| Sealed value v1 (`0x01`‖nonce‖ct+tag) | Python and Go | Yes | Byte-identical across both. Unknown version bytes fail with an error naming the version. |
| Record AAD `strongbox/record/v1\|coll\|id\|banner\|version` | Python and Go before app scoping | Yes (`aad_version = 1` rows) | App-bound successor is described in [ARCHITECTURE.md](ARCHITECTURE.md#encryption-contexts). Legacy rows are re-sealed under the new context on their next write. |
| Data-key wrap AAD `strongbox/datakey/v1\|id\|scope\|purpose` | Python and Go before app scoping | Yes (`aad_version = 1` keys) | Same as above. |
| Blob contexts `strongbox/blob*/v1\|…` | Retired Python implementation | **No** | Go has always used `…/v2`. A Python-era database is refused before any blob is read (below). |
| Blob contexts `strongbox/blob*/v2\|id\|banner` | Go before app scoping | Yes (`aad_version = 2` blobs) | Objects keep their context for life; rewriting ciphertext to change AAD is not done. |
| Local dev keyring JSON `{"active","keys"}` | Python and Go | Yes | Development only. |
| Database schema created by Python (`schema_info` marker, no `schema_migrations`) | Retired Python implementation | **No. `strongbox init` refuses** with `ErrLegacyPythonSchema` | Prevents a half-applied migration against an incompatible layout. |
| Database schema `0001_init.sql` (unscoped tables) | Go before app scoping | Yes, through `0002` | Existing rows are mapped to the `_legacy` scope, which no request context can select, until an operator assigns them (below). |

Migration 0012 adds nullable `attachment_id` to records and revisions. A live record's
foreign key binds the file to its app, owner and active state. Existing records acquire
no link. Sealed export and restore preserve both columns. Only live links pin bytes.
See the [attachment and retry contract](../examples/dreamcatcher/README.md#file-lifetime-and-retries).

## Decision on Python-era data

The Python implementation existed for three commits (14f9a5f through 6d54d45) before the Go rewrite and
was never deployed by this project. There is no Python-era production data to convert, so no converter
is shipped. Strongbox fails clearly instead:

- `SBX1` objects return `integrity_violation: legacy SBX1 ciphertext is not supported`.
- A Python-initialized database stops `strongbox init` before any statement runs.
- Unknown sealed versions and unknown stream magic return errors that name the format.

If a Python-era database is found later, the path is a Go converter run against a copy with
`--dry-run`. It would re-key `SBX1` objects through a non-`fips140=only` build in an isolated
environment, then verify every object with the normal Go reader before switching. That is out of scope
until such data exists. Ciphertext is never discarded and databases are never reset to make an upgrade
pass.

## Pre-scoping Go data (`0001` → `0002`)

Migration `0002` adds an `app` column to every app-owned table and fills existing rows with the
sentinel `_legacy`. The request context check (`ctx_app()`) accepts only `^[a-z][a-z0-9-]{1,39}:(dev|test|staging|prod)$`,
so legacy rows are invisible to every request. They stay owned by their original `created_by`
subject with `private` visibility. Nothing becomes shared by default.

Assign them explicitly with the owner-role CLI:

```bash
strongbox admin legacy-assign --app notes:prod --dry-run   # counts per table, no writes
strongbox admin legacy-assign --app notes:prod --batch 500  # resumable: each batch commits on its own
strongbox admin legacy-assign --app notes:prod --verify     # every legacy row decrypts under its old context
```

Legacy rows keep `aad_version = 1` (records, data keys) or `2` (blobs), so their ciphertext still
authenticates after the move. Records are re-sealed with the app-bound context on their next update.


## Sealed export bundles

Format 2 encrypts every table and authenticates the manifest, including exact file inventory,
row/byte counts and source database/object namespace. Each table uses a fresh stream key and SBX2
64 KiB segments. See [format details and canonical authentication](RECOVERY_AND_RECONCILIATION.md#format-2).
Format 1 remains readable with explicit legacy acceptance at the CLI; it has no manifest authentication.
