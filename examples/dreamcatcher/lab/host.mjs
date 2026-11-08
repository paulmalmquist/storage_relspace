import http from 'node:http';
import { createHash, randomBytes } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import { join } from 'node:path';
import {
  bounded,
  failure,
  json,
  jsonInput,
  profiles,
  RequestError,
  storageHandler,
} from '../host/storage.mjs';
import { subjects, rows } from './fixtures.mjs';

const random = () => randomBytes(32).toString('hex');
async function listen(server, port, host = '127.0.0.1') {
  await new Promise((ok, fail) => {
    server.once('error', fail);
    server.listen(port, host, ok);
  });
  return server;
}
const signin =
  '<!doctype html><meta name="viewport" content="width=device-width"><title>Dreamcatcher demo</title><h1>Open the synthetic workspace</h1><form method="post" action="/_demo/session"><button name="user" value="builder">Open as Alice</button> <button name="user" value="viewer">Open as Bob</button></form>';
export async function startHost({
  dir,
  strongboxOrigin,
  subjectToken,
  gatewayPort = 18400,
  ports = [18401, 18402],
  upstreams,
  edgeBind = '127.0.0.1',
}) {
  const bindings = {},
    tokens = new Map(),
    sessions = new Map(),
    revoked = new Set(),
    deniedPrograms = new Set();
  const gatewayOrigin = 'http://127.0.0.1:' + gatewayPort;
  for (const [slug, profile] of Object.entries(profiles)) {
    bindings[slug] = {
      submissionId: createHash('sha256')
        .update(await readFile(join(dir, slug + '.zip')))
        .digest('hex'),
      profile: slug,
      strongboxApp: profile.files ? 'supplier' : 'readiness',
      marking: 'UNCONTROLLED',
    };
    for (const user of Object.keys(subjects)) {
      const s = { user, slug, token: random(), cookie: random() };
      tokens.set(s.token, s);
      sessions.set(slug + '/' + user, s);
    }
  }
  const storage = storageHandler({ gatewayOrigin, strongboxOrigin, bindings, subjects, subjectToken });
  const gateway = http.createServer(async (req, res) => {
    try {
      if (req.url.endsWith('/storage')) {
        await storage(req, res);
        return;
      }
      const path = /^\/api\/v2\/runtime\/([a-z-]+)\/(context|queries)$/.exec(req.url);
      const session = tokens.get(req.headers.authorization?.replace(/^Bearer /, ''));
      if (
        !session ||
        !path ||
        session.slug !== path[1] ||
        revoked.has(session.slug + '/' + session.user)
      )
        throw new RequestError(403, 'access_denied');
      const slug = session.slug,
        profile = profiles[slug];
      if (req.method === 'GET' && path[2] === 'context') {
        json(res, 200, {
          app_id: slug,
          submission_id: bindings[slug].submissionId,
          user: { id: session.user },
          queries: [profile.query],
        });
        return;
      }
      if (req.method !== 'POST' || path[2] !== 'queries') throw new RequestError(404, 'not_found');
      const input = await jsonInput(req);
      if (
        input.reference !== profile.query ||
        Object.keys(input.parameters ?? {}).join() !== 'program_id'
      )
        throw new RequestError(403, 'query_denied');
      const program = input.parameters.program_id;
      const allowed =
        (session.user === 'builder' || program === 'program-a') &&
        !deniedPrograms.has(session.user + '/' + program);
      json(res, 200, {
        rows: allowed ? rows[slug].filter((r) => r.program_id === program) : [],
        truncated: false,
      });
    } catch (e) {
      failure(res, e);
    }
  });
  await listen(gateway, gatewayPort);
  const edges = [];
  try {
    for (const [index, slug] of Object.keys(profiles).entries()) {
      const port = ports[index],
        external = 'http://127.0.0.1:' + port,
        cookieName = 'dc_' + slug.replaceAll('-', '_');
      const edge = http.createServer(async (req, res) => {
        res.setHeader('cache-control', 'no-store');
        res.setHeader('x-content-type-options', 'nosniff');
        res.setHeader(
          'content-security-policy',
          "default-src 'none'; script-src 'self'; connect-src 'self'; style-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'",
        );
        try {
          if (req.headers.host !== '127.0.0.1:' + port) throw new RequestError(403, 'invalid_host');
          if (req.method !== 'GET' && req.headers.origin !== external)
            throw new RequestError(403, 'origin_denied');
          if (req.url === '/_demo/session' && req.method === 'POST') {
            const user = new URLSearchParams((await bounded(req, 128)).toString()).get('user');
            const session = sessions.get(slug + '/' + user);
            if (!session) throw new RequestError(403, 'unknown_demo_user');
            res
              .writeHead(303, {
                'set-cookie': cookieName + '=' + session.cookie + '; Path=/; HttpOnly; SameSite=Strict',
                location: '/',
              })
              .end();
            return;
          }
          if (req.url === '/_demo/accounts' && req.method === 'GET') {
            res.writeHead(200, { 'content-type': 'text/html' }).end(signin);
            return;
          }
          const cookie = req.headers.cookie
            ?.split(';')
            .map((s) => s.trim())
            .find((s) => s.startsWith(cookieName + '='))
            ?.slice(cookieName.length + 1);
          const session = [...sessions.values()].find((s) => s.slug === slug && s.cookie === cookie);
          if (!session) {
            if (req.method === 'GET' && req.url === '/') {
              res.writeHead(200, { 'content-type': 'text/html' }).end(signin);
              return;
            }
            throw new RequestError(401, 'sign_in');
          }
          if (revoked.has(slug + '/' + session.user)) throw new RequestError(403, 'access_denied');
          if (
            !['/', '/app.js', '/style.css', '/view.json', '/api/rows', '/api/entries'].includes(
              req.url,
            ) ||
            !['GET', 'POST'].includes(req.method)
          )
            throw new RequestError(404, 'not_found');
          const body = req.method === 'POST' ? await bounded(req, 65536) : undefined;
          const reply = await fetch(upstreams[index] + req.url, {
            method: req.method,
            headers: {
              'x-dreamcatcher-runtime-token': session.token,
              'content-type': 'application/json',
            },
            body,
            redirect: 'error',
            signal: AbortSignal.timeout(26000),
          });
          res
            .writeHead(reply.status, {
              'content-type': reply.headers.get('content-type') ?? 'application/json',
            })
            .end(await bounded(reply.body, 2 << 20));
        } catch (e) {
          failure(res, e);
        }
      });
      edges.push(await listen(edge, port, edgeBind));
    }
  } catch (e) {
    for (const server of [gateway, ...edges]) server.close();
    throw e;
  }
  return {
    bindings,
    revoked,
    deniedPrograms,
    close: () =>
      Promise.all(
        [gateway, ...edges].map(
          (s) =>
            new Promise((ok) => {
              s.close(ok);
              s.closeAllConnections();
            }),
        ),
      ),
  };
}
