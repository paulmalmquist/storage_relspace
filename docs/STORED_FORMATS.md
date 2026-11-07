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
| Record AAD `strongbox/record/v1\|coll\|id\|banner\|version` | Python and Go | Yes | Byte-identical across both. |
| Data-key wrap AAD `strongbox/datakey/v1\|id\|scope\|purpose` | Python and Go | Yes | Byte-identical across both. |
| Blob contexts `strongbox/blob*/v1\|…` | Retired Python implementation | **No** | Go has always used `…/v2`. A Python-era database is refused before any blob is read (below). |
| Blob contexts `strongbox/blob*/v2\|id\|banner` | Go | Yes | |
| Local dev keyring JSON `{"active","keys"}` | Python and Go | Yes | Development only. |
| Database schema created by Python (`schema_info` marker, no `schema_migrations`) | Retired Python implementation | **No. `strongbox init` refuses** with `ErrLegacyPythonSchema` | Prevents a half-applied migration against an incompatible layout. |
| Database schema `0001_init.sql` | Go | Yes | |

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
