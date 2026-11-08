// This module is shipped inside each source ZIP. All user credentials come from
// the private Dreamcatcher edge, one request at a time.
import http from 'node:http';
import { readFile } from 'node:fs/promises';

const app = process.env.DC_APP_ID;
const gateway = new URL(process.env.DC_GATEWAY_ORIGIN);
if (
  !/^[\w-]{1,80}$/.test(app ?? '') ||
  gateway.origin !== gateway.href.replace(/\/$/, '') ||
  !(
    gateway.protocol === 'https:' ||
    (gateway.protocol === 'http:' && ['127.0.0.1', 'localhost', '[::1]'].includes(gateway.hostname))
  )
) {
  throw Error('Set DC_APP_ID and a trusted DC_GATEWAY_ORIGIN');
}
const base = '/api/v2/runtime/' + app;
const manifest = JSON.parse(await readFile(new URL('./dreamcatcher.json', import.meta.url)));
const assets = new Map();
for (const [route, name, type] of [
  ['/', 'index.html', 'text/html'],
  ['/app.js', 'app.js', 'text/javascript'],
  ['/style.css', 'style.css', 'text/css'],
  ['/view.json', 'view.json', 'application/json'],
])
  assets.set(route, { type, bytes: await readFile(new URL('./dist/' + name, import.meta.url)) });

const server = http.createServer(async (req, res) => {
  res.setHeader('Cache-Control', 'no-store');
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader(
    'Content-Security-Policy',
    "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'",
  );
  if (req.method === 'GET' && ['/healthz', '/readyz'].includes(req.url)) {
    res.end('ok');
    return;
  }
  const token = req.headers['x-dreamcatcher-runtime-token'];
  if (typeof token !== 'string' || !token) {
    res.writeHead(401).end();
    return;
  }
  const call = (path, body) =>
    fetch(new URL(path, gateway), {
      method: body === undefined ? 'GET' : 'POST',
      headers: { authorization: 'Bearer ' + token, 'content-type': 'application/json' },
      body: body === undefined ? undefined : JSON.stringify(body),
      redirect: 'error',
      signal: AbortSignal.timeout(20000),
    });
  try {
    const check = await call(base + '/context');
    if (!check.ok) {
      await check.body?.cancel();
      res.writeHead(check.status).end();
      return;
    }
    const context = await check.json();
    if (
      context.app_id !== app ||
      !context.submission_id ||
      !context.queries?.includes(manifest.queries[0])
    ) {
      res.writeHead(403).end();
      return;
    }
    const asset = assets.get(req.url);
    if (asset && ['GET', 'HEAD'].includes(req.method)) {
      res.writeHead(200, { 'content-type': asset.type });
      res.end(req.method === 'HEAD' ? undefined : asset.bytes);
      return;
    }
    if (req.method !== 'POST' || !['/api/rows', '/api/entries'].includes(req.url)) {
      res.writeHead(404).end();
      return;
    }
    const chunks = [];
    let total = 0;
    for await (const chunk of req) {
      total += chunk.length;
      if (total > 65536) {
        res.writeHead(413).end();
        return;
      }
      chunks.push(chunk);
    }
    let input;
    try {
      input = JSON.parse(Buffer.concat(chunks));
    } catch {
      res.writeHead(400).end();
      return;
    }
    if (!input || typeof input !== 'object' || !/^[a-zA-Z0-9_-]{1,80}$/.test(input.program_id ?? '')) {
      res.writeHead(422).end();
      return;
    }
    const reply =
      req.url === '/api/rows'
        ? await call(base + '/queries', {
            reference: manifest.queries[0],
            parameters: { program_id: input.program_id },
          })
        : await call(base + '/storage', input);
    const bytes = Buffer.from(await reply.arrayBuffer());
    res.writeHead(reply.status, {
      'content-type': reply.headers.get('content-type') ?? 'application/json',
    });
    res.end(bytes);
  } catch {
    res.writeHead(503, { 'content-type': 'application/json' }).end('{"error":"gateway_unavailable"}');
  }
});
server.requestTimeout = 25000;
server.listen(Number(process.env.PORT ?? 8080), process.env.BIND ?? '0.0.0.0');
