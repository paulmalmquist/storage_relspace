import { test } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import { once } from 'node:events';
import { json, storageHandler } from './storage.mjs';

test('the bridge checks the end user and sends workload credentials only to Strongbox', async (t) => {
  async function server(fn) {
    const s = http.createServer(fn);
    s.listen(0, '127.0.0.1');
    await once(s, 'listening');
    t.after(
      () =>
        new Promise((ok) => {
          s.close(ok);
          s.closeAllConnections();
        }),
    );
    return 'http://127.0.0.1:' + s.address().port;
  }
  const dcHeaders = [],
    sbHeaders = [];
  let actualSubject = 'wrong-user';
  const gateway = await server((req, res) => {
    dcHeaders.push(req.headers);
    json(
      res,
      200,
      req.method === 'GET'
        ? {
            app_id: 'readiness-app',
            submission_id: 's1',
            user: { id: 'alice' },
            queries: ['bq-build-readiness@1.0.0'],
          }
        : { rows: [{ program_id: 'p', assembly_id: 'k' }] },
    );
  });
  const strongbox = await server((req, res) => {
    sbHeaders.push({ path: req.url, headers: req.headers });
    json(
      res,
      200,
      req.url === '/v1/whoami'
        ? { subject: actualSubject, actor: null, kind: 'user' }
        : { items: [], next_cursor: null },
    );
  });
  const bridge = await server(
    storageHandler({
      gatewayOrigin: gateway,
      strongboxOrigin: strongbox,
      bindings: {
        'readiness-app': {
          submissionId: 's1',
          strongboxApp: 'readiness',
          profile: 'readiness-notes',
          marking: 'UNCONTROLLED',
        },
      },
      subjects: { alice: 'expected-user' },
      subjectToken: async () => 'end-user',
      invokerToken: async () => 'workload',
    }),
  );
  const call = () =>
    fetch(bridge + '/api/v2/runtime/readiness-app/storage', {
      method: 'POST',
      headers: { authorization: 'Bearer runtime', 'x-serverless-authorization': 'Bearer forged' },
      body: JSON.stringify({ action: 'list', program_id: 'p', row_id: 'k' }),
    });
  let r = await call();
  assert.equal(r.status, 403);
  await r.body.cancel();
  assert.deepEqual(
    sbHeaders.map((x) => x.path),
    ['/v1/whoami'],
  );
  actualSubject = 'expected-user';
  r = await call();
  assert.equal(r.status, 200);
  await r.body.cancel();
  assert.equal(sbHeaders.at(-1).path, '/v1/apps/readiness/collections/readiness_notes/query');
  assert(
    dcHeaders.every((h) => h.authorization === 'Bearer runtime' && !h['x-serverless-authorization']),
  );
  assert(
    sbHeaders.every(
      (v) =>
        v.headers.authorization === 'Bearer end-user' &&
        v.headers['x-serverless-authorization'] === 'Bearer workload',
    ),
  );
});
