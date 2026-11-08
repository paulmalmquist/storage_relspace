import { test } from 'node:test';
import assert from 'node:assert/strict';
import { fork } from 'node:child_process';
import { randomUUID } from 'node:crypto';
import { once } from 'node:events';
import { exchangeCredential } from '../host/serve.mjs';

test('token exchange requests an audience-bound ID token, fails closed on a different type', async () => {
  const options = {
    url: 'https://identity.fixture.invalid/exchange',
    clientId: 'bridge',
    clientSecret: 'private-fixture',
    audience: 'strongbox-demo',
  };
  let type = 'urn:ietf:params:oauth:token-type:id_token';
  const exchange = exchangeCredential(options, async (url, req) => {
    assert.equal(url.href, options.url);
    assert.equal(req.body.get('audience'), options.audience);
    assert.equal(req.body.get('subject_token'), 'per-request-runtime');
    assert.equal(req.redirect, 'error');
    return Response.json({ issued_token_type: type, access_token: 'subject-id-token' });
  });
  assert.equal(await exchange({ token: 'per-request-runtime' }), 'subject-id-token');
  type = 'bearer';
  await assert.rejects(exchange({ token: 'per-request-runtime' }));
});

test(
  'uploaded applications with PostgreSQL, restricted Strongbox login, local keys and objects',
  { timeout: 120000 },
  async (t) => {
    let child;
    async function launch() {
      child = fork(new URL('./start.mjs', import.meta.url), [], {
        stdio: ['ignore', 'pipe', 'pipe', 'ipc'],
      });
      let logs = '';
      child.stderr.on('data', (c) => {
        logs = (logs + c).slice(-4000);
      });
      await new Promise((resolve, reject) => {
        const timer = setTimeout(() => reject(Error('lab startup timeout: ' + logs)), 30000);
        child.once('message', (m) => {
          clearTimeout(timer);
          m === 'ready' ? resolve() : reject(Error('invalid startup event'));
        });
        child.once('exit', (code) => {
          clearTimeout(timer);
          reject(Error('startup exit ' + code + ': ' + logs));
        });
      });
    }
    async function stop() {
      if (!child || child.exitCode !== null || child.signalCode) return;
      const exited = once(child, 'exit');
      child.disconnect();
      child.kill();
      await exited;
    }
    t.after(stop);
    await launch();
    const scopes = ['http://127.0.0.1:18401', 'http://127.0.0.1:18402'];
    async function sign(port, user) {
      const base = scopes[port];
      const reply = await fetch(base + '/_demo/session', {
        method: 'POST',
        redirect: 'manual',
        body: new URLSearchParams({ user }),
        headers: { origin: base },
      });
      assert.equal(reply.status, 303);
      const cookie = reply.headers.getSetCookie()[0].split(';')[0];
      return async (path, body, extras = {}) =>
        fetch(base + path, {
          method: body ? 'POST' : 'GET',
          headers: { cookie, origin: base, 'content-type': 'application/json', ...extras },
          body: body ? JSON.stringify(body) : undefined,
          redirect: 'error',
        });
    }
    const data = async (p, status = 200) => {
      const r = await p;
      const bytes = await r.text();
      assert.equal(r.status, status, bytes);
      return JSON.parse(bytes);
    };
    let a, b, sa, sb;
    async function users() {
      [a, b, sa, sb] = await Promise.all([
        sign(0, 'builder'),
        sign(0, 'viewer'),
        sign(1, 'builder'),
        sign(1, 'viewer'),
      ]);
    }
    await users();
    const context = { program_id: 'program-a', row_id: 'DEMO-A101' },
      line = { program_id: 'program-a', row_id: 'DEMO-PO101' };
    const entries = (call, body) => call('/api/entries', body);
    const note = {
      ...context,
      action: 'save',
      note: 'Check assembly sequence ' + randomUUID(),
      status: 'Watching',
      operation_id: randomUUID(),
    };
    const bytes = Buffer.from([0, 13, 10, 127, 170, 255]),
      evidence = {
        ...line,
        action: 'save',
        note: 'Follow up on the revised delivery',
        status: 'Open',
        operation_id: randomUUID(),
        file: { name: 'receipt.bin', base64: bytes.toString('base64') },
      };
    let saved, file, secret;
    await t.test(
      'bundle runs behind the edge and the query broker enforces per-user program access',
      async () => {
        assert.match(await (await a('/')).text(), /id="editor"/);
        for (const path of ['/server.mjs', '/.env', '/api/v2/runtime/supplier-evidence/context'])
          assert.equal((await a(path)).status, 404);
        assert.equal(
          (await a('/api/rows', { program_id: 'program-a' }, { origin: 'https://unrelated.invalid' }))
            .status,
          403,
        );
        assert.equal(
          (await data(a('/api/rows', { program_id: 'program-a' }))).rows[0].assembly_id,
          context.row_id,
        );
        assert.equal(
          (
            await data(
              b('/api/rows', { program_id: 'program-b' }, { 'x-dreamcatcher-runtime-token': 'forged' }),
            )
          ).rows.length,
          0,
        );
      },
    );
    await t.test(
      'private save retries exactly once, stale edit preserves the winning version',
      async () => {
        saved = await data(entries(a, note), 201);
        const retry = await data(entries(a, note), 201);
        assert.equal(retry.id, saved.id);
        assert.equal(retry.version, 1);
        assert(
          !(await data(entries(b, { ...context, action: 'list' }))).items.some((x) => x.id === saved.id),
        );
        const edit = {
          ...note,
          id: saved.id,
          expected_version: 1,
          operation_id: randomUUID(),
          note: 'Reviewed assembly sequence',
          status: 'Ready',
        };
        assert.equal((await data(entries(a, edit))).version, 2);
        assert.equal((await data(entries(a, edit))).version, 2);
        await data(entries(a, { ...edit, operation_id: randomUUID(), note: 'stale' }), 412);
        await data(entries(a, { ...edit, app: 'supplier', operation_id: randomUUID() }), 422);
      },
    );
    await t.test(
      'shared evidence pins an encrypted file, survives retry, and is accessed only through its entitled row',
      async () => {
        file = await data(entries(sa, evidence), 201);
        assert.equal((await data(entries(sa, evidence), 201)).id, file.id);
        assert.equal(file.has_file, true);
        const list = await data(entries(sb, { ...line, action: 'list' }));
        assert(list.items.some((x) => x.id === file.id));
        assert(!('attachment_id' in file));
        const download = await entries(sb, { ...line, action: 'download', id: file.id });
        assert.equal(download.status, 200);
        assert.deepEqual(Buffer.from(await download.arrayBuffer()), bytes);
        await data(entries(sb, { ...line, row_id: 'DEMO-PO102', action: 'download', id: file.id }), 404);
        await data(entries(b, { ...context, action: 'download', id: file.id }), 404);
        secret = await data(
          entries(sa, {
            ...evidence,
            program_id: 'program-b',
            row_id: 'DEMO-PO201',
            operation_id: randomUUID(),
          }),
          201,
        );
        await data(
          entries(sb, {
            program_id: 'program-b',
            row_id: 'DEMO-PO201',
            action: 'download',
            id: secret.id,
          }),
          404,
        );
      },
    );
    await t.test('full service restart retains both saves and the exact evidence bytes', async () => {
      await stop();
      await launch();
      await users();
      assert(
        (await data(entries(a, { ...context, action: 'list' }))).items.some(
          (x) => x.id === saved.id && x.version === 2,
        ),
      );
      assert.equal((await data(entries(sa, evidence), 201)).id, file.id);
      const r = await entries(sb, { ...line, action: 'download', id: file.id });
      assert.equal(r.status, 200);
      assert.deepEqual(Buffer.from(await r.arrayBuffer()), bytes);
    });
    if (process.env.DC_REFERENCE_FIXTURES)
      await t.test(
        'reference Dreamcatcher releases query entitled rows and persist through the exact submitted bundles',
        async () => {
          const { referenceStory } = await import('./reference-smoke.mjs');
          await referenceStory(process.env.DC_REFERENCE_FIXTURES);
        },
      );
    if (process.env.DC_TEST_BROWSER === '1')
      await t.test('Chromium completes the upload, reload and download workflows', async () => {
        const { browserStory } = await import('./browser.mjs');
        await browserStory(scopes);
      });
    async function control(action) {
      const applied = once(child, 'message');
      child.send(action);
      assert.equal((await applied)[0], 'applied');
    }
    await t.test(
      'warehouse entitlement loss and release revocation apply to the next read, download and retry',
      async () => {
        await control({ action: 'denyProgram', user: 'viewer', program: 'program-a' });
        await data(entries(sb, { ...line, action: 'download', id: file.id }), 404);
        await data(entries(sb, { ...line, action: 'list' }), 404);
        await control({ action: 'revoke', app: 'supplier-evidence', user: 'builder' });
        assert.equal((await sa('/')).status, 403);
        await data(entries(sa, evidence), 403);
        assert.equal((await a('/')).status, 200);
      },
    );
  },
);
