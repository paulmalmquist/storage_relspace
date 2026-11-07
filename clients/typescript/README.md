# @strongbox/client

TypeScript client for the Strongbox API, for Node 22+ servers and browsers. Not published; build it
from this directory (`npm ci && npm run build`).

```ts
import { Strongbox, gcpWorkloadIdentity, userToken, isConflict } from "@strongbox/client";

// Server workload (Cloud Run): its own identity, optionally acting for a user.
const sb = new Strongbox({ baseUrl: process.env.STRONGBOX_URL!, auth: gcpWorkloadIdentity("https://strongbox.example") });
// Browser: the signed-in user's token from your auth library. Never ship workload credentials.
const web = new Strongbox({ baseUrl: "/strongbox", auth: userToken(() => auth.currentUser!.getIdToken()) });

const notes = sb.app("notes");
const rec = await notes.createRecord("todo", { data: { title: "x" } });           // private by default
await notes.mutate("todo", rec.id, (d) => ({ ...d, done: true }));                 // CAS with conflict recovery
await notes.restore("todo", rec.id, 1, 2);                                          // undo
```

- Wire types are generated from `internal/api/openapi.json` (`npm run generate`); CI fails if they drift.
- Mutations carry an operation ID (pass `operationId` to recover a call whose response you lost).
- Retries: up to 4 attempts on 429/502/503/504, network errors and `operation_in_progress`, honouring
  `Retry-After`. Conflicts (`412`) are never retried blindly; use `mutate` or handle `isConflict`.
- Every call takes `{ signal }` for cancellation; each attempt also has a timeout (`timeoutMs`).
- Large blobs: `putLargeBlob` uses upload sessions and can resume with `{ resume: uploadId }`.

Tests: `npm test` runs unit tests; with a live server (`scripts/live-server.sh`) it also runs the
contract tests (private state, team sharing, conflict recovery, undo, lost responses, blobs).
`npm run example` runs `examples/demo.ts` against the same server.
