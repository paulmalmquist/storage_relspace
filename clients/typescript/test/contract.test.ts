// Contract tests against a running Strongbox (scripts/live-server.sh). They skip without
// STRONGBOX_URL, except when STRONGBOX_REQUIRE_INTEGRATION=1 (CI), where a missing server fails.
import { test } from "node:test";
import assert from "node:assert/strict";
import { Strongbox, StrongboxError, isConflict, isNotFound, staticToken, newOperationId } from "../src/index.ts";

const url = process.env.STRONGBOX_URL;
const required = process.env.STRONGBOX_REQUIRE_INTEGRATION === "1";
const skip = !url && !required ? "STRONGBOX_URL not set" : false;
const as = (who: "ALICE" | "BOB" | "CAROL") => {
  if (!url) throw new Error("STRONGBOX_URL is required (STRONGBOX_REQUIRE_INTEGRATION=1)");
  return new Strongbox({ baseUrl: url, auth: staticToken(process.env[`STRONGBOX_TOKEN_${who}`] ?? "") }).app(process.env.STRONGBOX_APP ?? "demo");
};
const coll = `ts_${Date.now().toString(36)}`;

test("private state, team sharing, conflict recovery and undo", { skip }, async () => {
  const alice = as("ALICE"), bob = as("BOB"), carol = as("CAROL");
  await alice.createCollection({ name: coll, marking: "CUI//SP-EXPT", indexed_fields: ["kind"] });

  // Private by default.
  const draft = await alice.createRecord(coll, { data: { kind: "draft", text: "mine" } });
  assert.equal(draft.visibility, "private");
  await assert.rejects(bob.getRecord(coll, draft.id), isNotFound);
  assert.equal((await bob.query(coll, { kind: "draft" })).items.length, 0, "hidden rows never reach a page");

  // Team sharing: Bob sees it through the team; Carol (not in the team) does not.
  const team = await alice.createTeam(`team-${coll}`);
  await alice.setTeamMember(team.id, "bob@example.com", "editor");
  await alice.share(coll, draft.id, "team", team.id);
  assert.equal((await bob.getRecord(coll, draft.id)).data?.text, "mine");
  await assert.rejects(carol.getRecord(coll, draft.id), isNotFound);

  // Conflict recovery: both edit version 1; the second write gets 412, mutate() re-applies.
  await bob.updateRecord(coll, draft.id, 1, { data: { kind: "draft", text: "bob" } });
  await assert.rejects(alice.updateRecord(coll, draft.id, 1, { data: { kind: "draft", text: "alice" } }), isConflict);
  const merged = await alice.mutate(coll, draft.id, (d) => ({ ...d, text: `${d.text as string}+alice` }));
  assert.equal(merged.data?.text, "bob+alice");
  assert.equal(merged.version, 3);

  // Undo: restore version 1 as version 4.
  const undone = await alice.restore(coll, draft.id, 1, 3);
  assert.equal(undone.version, 4);
  assert.equal(undone.data?.text, "mine");
  const hist = await alice.history(coll, draft.id);
  assert.deepEqual(hist.items.map((r) => r.op), ["restore", "update", "update", "create"]);

  // Revocation applies to the next request.
  await alice.share(coll, draft.id, "private");
  await assert.rejects(bob.getRecord(coll, draft.id), isNotFound);
});

test("a lost response is recovered with the same operation ID", { skip }, async () => {
  const alice = as("ALICE");
  await alice.createCollection({ name: `${coll}_ops`, marking: "UNCONTROLLED" });
  const op = newOperationId();
  const first = await alice.createRecord(`${coll}_ops`, { data: { n: 1 } }, { operationId: op });
  const again = await alice.createRecord(`${coll}_ops`, { data: { n: 1 } }, { operationId: op });
  assert.equal(again.id, first.id);
  assert.equal(again.replayed, true);
  assert.equal((await alice.operation(op)).status, "succeeded");
  await assert.rejects(alice.createRecord(`${coll}_ops`, { data: { n: 2 } }, { operationId: op }),
    (e: unknown) => e instanceof StrongboxError && e.code === "idempotency_key_reused");
});

test("blobs: one request and an upload session", { skip }, async () => {
  const alice = as("ALICE");
  const small = crypto.getRandomValues(new Uint8Array(10_000));
  const b1 = await alice.putBlob(small, { marking: "CUI//SP-EXPT", filename: "small.bin", metadata: { k: "v" } });
  assert.deepEqual(await alice.readBlob(b1.id), small);
  const big = new Uint8Array(5 * 65536 + 123);
  for (let i = 0; i < big.length; i += 65536) crypto.getRandomValues(big.subarray(i, Math.min(i + 65536, big.length)));
  const b2 = await alice.putLargeBlob(big, { marking: "CUI//SP-EXPT", parallel: 3 });
  assert.equal(b2.size_bytes, big.length);
  assert.deepEqual(await alice.readBlob(b2.id), big);
  const u = await alice.usage();
  assert.ok(u.blobs >= 2 && u.reserved_bytes === 0);
});
