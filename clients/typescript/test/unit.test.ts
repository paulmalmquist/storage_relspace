import { test } from "node:test";
import assert from "node:assert/strict";
import { Strongbox, StrongboxError, isConflict, staticToken, gcpWorkloadIdentity } from "../src/index.ts";

type Call = { url: string; init: RequestInit };

function fakeFetch(responses: Array<() => Response | Promise<Response>>, calls: Call[]): typeof fetch {
  return (async (url: string | URL, init?: RequestInit) => {
    calls.push({ url: String(url), init: init ?? {} });
    const next = responses.shift();
    if (!next) throw new Error("unexpected request");
    return next();
  }) as typeof fetch;
}

const json = (status: number, body: unknown, headers: Record<string, string> = {}) =>
  new Response(JSON.stringify(body), { status, headers: { "Content-Type": "application/json", ...headers } });

const header = (c: Call, name: string) => new Headers(c.init.headers).get(name);

test("a mutation is retried with the same operation ID after 503 and a lost connection", async () => {
  const calls: Call[] = [];
  const sb = new Strongbox({ baseUrl: "http://sb/", auth: staticToken("t"), fetch: fakeFetch([
    () => json(503, { code: "unavailable", detail: "busy" }, { "Retry-After": "0" }),
    () => { throw new TypeError("connection reset"); },
    () => json(201, { id: "rec_1", version: 1 }),
  ], calls) });
  const rec = await sb.app("notes").createRecord("todo", { data: { a: 1 } });
  assert.equal(rec.id, "rec_1");
  assert.equal(calls.length, 3);
  const ids = calls.map((c) => header(c, "Idempotency-Key"));
  assert.ok(ids[0]?.startsWith("op-"));
  assert.deepEqual(new Set(ids).size, 1, "every attempt must carry the same operation ID");
  assert.equal(calls[0]!.url, "http://sb/v1/apps/notes/collections/todo/records");
  assert.equal(header(calls[0]!, "Authorization"), "Bearer t");
});

test("conflicts are not retried and surface as typed errors", async () => {
  const calls: Call[] = [];
  const sb = new Strongbox({ baseUrl: "http://sb", auth: staticToken("t"), fetch: fakeFetch([
    () => json(412, { code: "precondition_failed", detail: "record is at version 3, not 2", request_id: "r1" }),
  ], calls) });
  await assert.rejects(sb.app("notes").updateRecord("todo", "rec_1", 2, { data: {} }), (e: unknown) => {
    assert.ok(e instanceof StrongboxError && isConflict(e));
    assert.equal(e.status, 412);
    assert.equal(e.requestId, "r1");
    return true;
  });
  assert.equal(header(calls[0]!, "If-Match"), '"v2"');
  assert.equal(calls.length, 1);
});

test("retries are bounded", async () => {
  const calls: Call[] = [];
  const busy = () => json(429, { code: "rate_limited", detail: "slow down" }, { "Retry-After": "0" });
  const sb = new Strongbox({ baseUrl: "http://sb", auth: staticToken("t"), maxAttempts: 3, fetch: fakeFetch([busy, busy, busy, busy], calls) });
  await assert.rejects(sb.app("notes").usage(), (e: unknown) => e instanceof StrongboxError && e.code === "rate_limited");
  assert.equal(calls.length, 3);
});

test("mutate re-reads and re-applies after a conflict", async () => {
  const calls: Call[] = [];
  const sb = new Strongbox({ baseUrl: "http://sb", auth: staticToken("t"), fetch: fakeFetch([
    () => json(200, { id: "r", version: 1, data: { n: 1 } }),
    () => json(412, { code: "precondition_failed", detail: "moved" }),
    () => json(200, { id: "r", version: 2, data: { n: 5 } }),
    () => json(200, { id: "r", version: 3, data: { n: 6 } }),
  ], calls) });
  const out = await sb.app("a").mutate("c", "r", (d) => ({ ...d, n: (d.n as number) + 1 }));
  assert.equal(out.version, 3);
  assert.equal(JSON.parse(String(calls[3]!.init.body)).data.n, 6, "the change is applied to the latest version");
  assert.equal(header(calls[3]!, "If-Match"), '"v2"');
});

test("an aborted call stops waiting", async () => {
  const ac = new AbortController();
  const sb = new Strongbox({ baseUrl: "http://sb", auth: staticToken("t"), fetch: fakeFetch([
    () => { ac.abort(new Error("user cancelled")); return json(503, { code: "unavailable", detail: "" }, { "Retry-After": "5" }); },
  ], []) });
  await assert.rejects(sb.app("a").usage({ signal: ac.signal }), /user cancelled/);
});

test("workload credentials refuse to run in a browser", () => {
  (globalThis as { window?: unknown }).window = {};
  try {
    assert.throws(() => gcpWorkloadIdentity("https://strongbox"), /server-only/);
  } finally {
    delete (globalThis as { window?: unknown }).window;
  }
});
