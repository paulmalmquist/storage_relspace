// A walk through Strongbox from TypeScript: private state, team sharing, conflict recovery and
// undo. Run against scripts/live-server.sh:  . ./.live.env && npm run example
import { Strongbox, staticToken, isConflict, isNotFound } from "../src/index.ts";

const url = process.env.STRONGBOX_URL ?? "http://127.0.0.1:18181";
const app = (who: string) =>
  new Strongbox({ baseUrl: url, auth: staticToken(process.env[`STRONGBOX_TOKEN_${who}`] ?? "") }).app(process.env.STRONGBOX_APP ?? "demo");
const alice = app("ALICE"), bob = app("BOB");
const coll = `notes_${Date.now().toString(36)}`;

await alice.createCollection({ name: coll, marking: "CUI//SP-EXPT" });
const note = await alice.createRecord(coll, { data: { title: "Launch checklist", items: ["fuel"] } });
console.log(`alice saved ${note.id} (v${note.version}, ${note.visibility}, ${note.marking})`);

try {
  await bob.getRecord(coll, note.id);
} catch (e) {
  if (isNotFound(e)) console.log("bob cannot see it: private by default");
}

const team = await alice.createTeam(`ops-${coll}`);
await alice.setTeamMember(team.id, "bob@example.com", "editor");
await alice.share(coll, note.id, "team", team.id);
console.log("shared with team", team.name, "->", (await bob.getRecord(coll, note.id)).data);

// Bob and Alice both start from v1.
await bob.updateRecord(coll, note.id, 1, { data: { title: "Launch checklist", items: ["fuel", "weather"] } });
try {
  await alice.updateRecord(coll, note.id, 1, { data: { title: "Launch checklist", items: ["fuel", "range"] } });
} catch (e) {
  if (isConflict(e)) console.log("alice's stale write was refused:", e.detail);
}
const merged = await alice.mutate(coll, note.id, (d) => ({ ...d, items: [...(d.items as string[]), "range"] }));
console.log(`merged v${merged.version}:`, merged.data?.items);

const undone = await alice.restore(coll, note.id, 2, merged.version);
console.log(`undo to v2 wrote v${undone.version}:`, undone.data?.items);
const history = await alice.history(coll, note.id);
console.log("history:", history.items.map((r) => `v${r.version} ${r.op}`).join(", "));
