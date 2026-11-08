# Run a Dreamcatcher app with persistent storage

Two uploadable apps come with HTML, JavaScript and a Node 22 backend. Both read governed warehouse rows through the Dreamcatcher query broker. Strongbox stores the program and row keys, the user's note, its status, and optional evidence. Warehouse metrics stay in the query response.

| Upload | What to try |
|---|---|
| [Readiness notebook](uploads/readiness-notes.zip) | Open as Alice, select an assembly, mark it blocked, write a private note and reload. Open as Bob to check privacy. |
| [Supplier follow-ups](uploads/supplier-evidence.zip) | Select a PO line, add a follow-up with a small file and save. A second member with access to the same supplier query can read the entry and download the original bytes. |

## Start on a workstation

From the repository root, with Docker Compose installed, run

```sh
docker compose -f examples/dreamcatcher/compose.yaml up --build
```

Open [Readiness notebook](http://127.0.0.1:18401) or [Supplier follow-ups](http://127.0.0.1:18402). Use `/_demo/accounts` on either origin to switch between Alice and Bob. The PostgreSQL database, encrypted objects and local keys survive a stop and restart in named volumes. The launcher binds the two browser ports to loopback.

The Compose configuration passed validation with Compose 2.40.3. The full launch was tested using the native launcher below. It requires Go 1.26, PostgreSQL 16 client tools, a local PostgreSQL 16 server and Node 22.18 or later. On macOS or Linux, point it at your local disposable cluster.

```sh
export PG_ADMIN_URL=postgres://postgres@127.0.0.1:5432/postgres
bash examples/dreamcatcher/lab/native.sh
```

It creates its own randomly named database and restricted runtime login. Stop with Ctrl-C. Running the same command again reuses the database, keyring and files. Native state defaults to `.strongbox-dreamcatcher/` under the checkout. The demonstration uses synthetic warehouse rows, local development identities and an actual Strongbox HTTP server. The launcher executes only the two packages it builds from the fixture sources.

## Upload and port an app

1. Upload the app's **individual ZIP** through Dreamcatcher's hosted-app source intake. Its root contains `dreamcatcher.json`, `Dockerfile`, `server.mjs`, editable `src/app.js` and the built bundle under `dist/`. The image build takes an operator-approved Node image digest through `APPROVED_NODE_IMAGE`. There are no npm runtime dependencies.
2. For a work dataset, edit the exact query reference in the app manifest under [apps](apps) and the matching [profile](profiles.json). Configure the row key, label, metric, allowed statuses and program choices. Rebuild the two ZIPs with `make dreamcatcher-bundles`. The reference queries take a named string parameter `program_id` and return `program_id` and a stable string row key on each row. The storage adapter requires a matching row in the broker response. A large/truncated query needs an approved keyed lookup for validation or a bounded query that includes the selected row.
3. Register a distinct Strongbox app per Dreamcatcher app and environment. Apply migrations through **0013** and provision its members and ordinary record/blob scopes. Copy [bindings.example.json](host/bindings.example.json) into gateway-owned configuration. Map the actual Dreamcatcher app and approved submission IDs, the Strongbox app slug, the applicable marking and verified directory user IDs. Update the binding when you promote a new release. Sample classifications and markings are for synthetic data.
4. Set `DC_STORAGE_BINDINGS`, `STRONGBOX_URL` and a short-lived `STRONGBOX_OPERATOR_TOKEN`, then run `node examples/dreamcatcher/host/collections.mjs`. It creates the encrypted collections through the API and checks the schema and indexes on a repeated run. An incompatible deployed contract requires Strongbox's normal schema-change procedure. Remove the operator token from the runtime environment.
5. Route **only** `POST /api/v2/runtime/{app}/storage` on the trusted Dreamcatcher gateway to `node examples/dreamcatcher/host/serve.mjs`. Existing context and query routes continue to serve their Dreamcatcher handlers. The bridge reads `DC_GATEWAY_ORIGIN`, `STRONGBOX_URL`, `DC_STORAGE_BINDINGS`, `STRONGBOX_AUDIENCE`, `DC_TOKEN_EXCHANGE_URL`, `DC_TOKEN_CLIENT_ID` and `DC_TOKEN_CLIENT_SECRET`. It defaults to loopback port 8099. Its exchange client expects an identity service that accepts a Dreamcatcher runtime token and returns an end-user OIDC ID token for Strongbox. If your platform already holds the correct user token in the trusted edge session, supply that lookup as `storageHandler.subjectToken`. Strongbox `whoami` must match the configured directory subject. For a private Cloud Run service, the bridge can read a rotating workload ID token from `STRONGBOX_INVOKER_TOKEN_FILE` and send it as `X-Serverless-Authorization`. The end-user ID token stays in `Authorization`. Provisioning can run through your authenticated internal route.
6. Launch the reviewed backend behind Dreamcatcher's authenticated private edge with `DC_APP_ID`, `DC_GATEWAY_ORIGIN` and `PORT`. The edge replaces the runtime-token header, enforces the app origin and checks the release. Route the uploaded container's network access through the gateway. Keep the exchange credentials, Strongbox tokens and database access with trusted services.

The bundle rechecks the active context and calls the release's declared query. On each storage request the bridge independently verifies the active submission, reruns that same governed query for the user, resolves a fixed Strongbox app and collection, and calls the API as the verified user. This also covers edits, lists, downloads and retries. The sample keeps one 32 KiB file per evidence entry so that the encoded save fits the reference edge's 64 KiB request limit. Create another entry for another file. A save carries its operation ID and expected version in the request body because the reference edge admits a narrow header set.

## Reproduce the checks

- `bash examples/dreamcatcher/lab/native.sh --test` runs the HTTP contracts, including a complete service restart. Use a fresh `DC_LAB_STATE` directory for an independent run.
- With Playwright and Chromium installed, add `DC_TEST_BROWSER=1` to the same command. `PLAYWRIGHT_MODULE` may point to an installed ESM module and `CHROMIUM_PATH` to an existing Chromium executable. `DC_SCREENSHOTS` selects an optional screenshot directory.
- With a disposable reference Dreamcatcher running on loopback, `node examples/dreamcatcher/lab/submit.mjs http://127.0.0.1:8000 examples/dreamcatcher/uploads` registers two new synthetic apps, uploads the actual ZIPs and prints their queued submission receipts. This uses the reference local builder account.
- The optional [reference gateway contract](lab/reference-smoke.mjs) also exercises active releases against the reference runtime context and query endpoints. Set `DC_REFERENCE_FIXTURES` to a mode-0600 JSON file with `origin` and `apps` keyed by fixture slug. Each needs `app_id`, `submission_id`, `archive_sha256`, and two release-bound tokens at `tokens.builder` and `tokens.viewer`. Use the reference synthetic catalog/entitlements. Its viewer can query readiness in program A and lacks the supplier query group. The test verifies both denials and the owner's evidence download.
- [Recorded receipts, load measurements and test results](../../docs/evidence/dreamcatcher/README.md).

## File lifetime and retries

A managed `attachment_id` on a live record pins an active blob with the same app and owner. Set it when creating a record or in a versioned update. Omit it on update to preserve the file, or send an empty string to detach. Only the record owner can change the link. Other permitted editors can edit the record contents. The record marking must cover the blob marking. Record reads, history and receipt replay show the link only while the caller can read the file. The database rejects deletion, shredding or separate owner transfer while a live link exists. Detach before transfer. A soft delete releases the pin. Undoing an old attachment requires the file to remain active and accessible. Older records default to having no managed link.

File upload and record creation use separate Strongbox calls. The sample retries both with stable operation IDs and discards the uploaded file on a definitive record rejection. An interrupted save can leave an active, unlinked file until the original save is retried. The object reconciler preserves such files because they have valid blob rows. A single atomic transaction covers record changes, including the link, after the upload.
