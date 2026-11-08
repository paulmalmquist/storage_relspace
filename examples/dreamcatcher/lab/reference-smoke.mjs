// Optional joined contract against a local Dreamcatcher with active fixture releases.
// The fixture file (0600) contains per-release builder/viewer tokens and submission receipts.
import assert from 'node:assert/strict';
import http from 'node:http';
import { spawn } from 'node:child_process';
import { once } from 'node:events';
import { readFile } from 'node:fs/promises';
import { join } from 'node:path';
import { createHash, randomUUID } from 'node:crypto';
import { bounded, storageHandler, profiles } from '../host/storage.mjs';
import { subjects } from './fixtures.mjs';
import { sb } from './provision.mjs';

export async function referenceStory(file) {
  const { origin, apps } = JSON.parse(await readFile(file));
  const base = new URL(origin);
  assert.equal(base.hostname, '127.0.0.1');
  assert.equal(base.protocol, 'http:');
  const bindings = {},
    dir = join(process.env.DC_LAB_STATE, 'uploads');
  for (const [slug, a] of Object.entries(apps)) {
    assert.equal(
      createHash('sha256')
        .update(await readFile(join(dir, slug + '.zip')))
        .digest('hex'),
      a.archive_sha256,
    );
    bindings[a.app_id] = {
      profile: slug,
      submissionId: a.submission_id,
      strongboxApp: profiles[slug].files ? 'supplier' : 'readiness',
      marking: 'UNCONTROLLED',
    };
  }
  const storage = storageHandler({
    gatewayOrigin: base.origin,
    strongboxOrigin: 'http://127.0.0.1:18410',
    bindings,
    subjects,
    subjectToken: async ({ subject }) => sb('token', subject, '-ttl', '15m'),
  });
  const mux = http.createServer(async (req, res) => {
    if (req.url.endsWith('/storage')) return storage(req, res);
    try {
      assert.match(req.url, /^\/api\/v2\/runtime\/[a-zA-Z0-9-]+\/(context|queries)$/);
      const r = await fetch(base.origin + req.url, {
        method: req.method,
        headers: { authorization: req.headers.authorization, 'content-type': 'application/json' },
        body: req.method === 'GET' ? undefined : await bounded(req, 65536),
        redirect: 'error',
        signal: AbortSignal.timeout(5000),
      });
      res
        .writeHead(r.status, { 'content-type': 'application/json' })
        .end(await bounded(r.body, 1 << 20));
    } catch {
      res.writeHead(503).end();
    }
  });
  mux.listen(0, '127.0.0.1');
  await once(mux, 'listening');
  const gw = 'http://127.0.0.1:' + mux.address().port;
  try {
    for (const [index, [slug, a]] of Object.entries(apps).entries()) {
      const port = 18421 + index,
        backend = 'http://127.0.0.1:' + port;
      const proc = spawn(process.execPath, ['server.mjs'], {
        cwd: join(dir, slug),
        env: { DC_APP_ID: a.app_id, DC_GATEWAY_ORIGIN: gw, PORT: String(port), BIND: '127.0.0.1' },
        stdio: 'ignore',
      });
      try {
        for (let i = 0; i < 80; i++) {
          try {
            if ((await fetch(backend + '/readyz')).ok) break;
          } catch {}
          await new Promise((ok) => setTimeout(ok, 50));
        }
        const post = (path, user, input) =>
          fetch(backend + path, {
            method: 'POST',
            headers: {
              'content-type': 'application/json',
              'x-dreamcatcher-runtime-token': a.tokens[user],
            },
            body: JSON.stringify(input),
          });
        const rows = await post('/api/rows', 'builder', { program_id: 'program-a' });
        assert.equal(rows.status, 200);
        const key = (await rows.json()).rows[0][profiles[slug].key];
        const scope = { program_id: 'program-a', row_id: key };
        const hidden = await post('/api/rows', 'viewer', { program_id: 'program-b' });
        // The upstream demo viewer lacks the supplier query group entirely. The
        // readiness query permits that user but filters out program-b.
        if (profiles[slug].files) assert.equal(hidden.status, 403);
        else {
          assert.equal(hidden.status, 200);
          assert.equal((await hidden.json()).rows.length, 0);
        }
        const save = {
          ...scope,
          action: 'save',
          note: 'Reference gateway round trip',
          status: profiles[slug].statuses[0],
          operation_id: randomUUID(),
        };
        if (profiles[slug].files)
          save.file = { name: 'test.txt', base64: Buffer.from('reference proof').toString('base64') };
        const r = await post('/api/entries', 'builder', save);
        assert.equal(r.status, 201, await r.clone().text());
        const rec = await r.json();
        const again = await post('/api/entries', 'builder', save);
        assert.equal((await again.json()).id, rec.id);
        const page = await post('/api/entries', 'viewer', { ...scope, action: 'list' });
        if (profiles[slug].files) assert.equal(page.status, 403);
        else {
          assert.equal(page.status, 200);
          assert(!(await page.json()).items.some((item) => item.id === rec.id));
        }
        if (profiles[slug].files) {
          const denied = await post('/api/entries', 'viewer', {
            ...scope,
            action: 'download',
            id: rec.id,
          });
          assert.equal(denied.status, 403);
          const blob = await post('/api/entries', 'builder', {
            ...scope,
            action: 'download',
            id: rec.id,
          });
          assert.equal(blob.status, 200);
          assert.equal(await blob.text(), 'reference proof');
        }
        const wrong = Object.values(apps).find((x) => x.app_id !== a.app_id);
        const forbidden = await fetch(backend + '/api/rows', {
          method: 'POST',
          headers: {
            'content-type': 'application/json',
            'x-dreamcatcher-runtime-token': wrong.tokens.builder,
          },
          body: JSON.stringify({ program_id: 'program-a' }),
        });
        assert([401, 403].includes(forbidden.status), 'another app token got ' + forbidden.status);
      } finally {
        const end = once(proc, 'exit');
        proc.kill();
        await end;
      }
    }
  } finally {
    await new Promise((ok) => {
      mux.close(ok);
      mux.closeAllConnections();
    });
  }
}
