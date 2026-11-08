// Starts only the two repository-owned fixtures created by pack. Requires a dedicated
// local demo database with a restricted login, never takes arbitrary upload paths.
import { spawn } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { resolve, join } from 'node:path';
import { mkdir } from 'node:fs/promises';
import { startHost } from './host.mjs';
import { sb, provision, collections } from './provision.mjs';
import { profiles } from '../host/storage.mjs';
import { randomBytes } from 'node:crypto';
if (process.env.STRONGBOX_ENV !== 'dev' || process.env.STRONGBOX_APP_ENV !== 'dev')
  throw Error('Local dev Strongbox required');
const root = fileURLToPath(new URL('../../../', import.meta.url));
const state = resolve(process.env.DC_LAB_STATE ?? '.strongbox-dreamcatcher');
await mkdir(state, { recursive: true, mode: 0o700 });
const dir = join(state, 'uploads'),
  bind = process.env.DC_LAB_CONTAINER === '1' ? '0.0.0.0' : '127.0.0.1';
if (!process.env.STRONGBOX_DEV_JWT_SECRET)
  process.env.STRONGBOX_DEV_JWT_SECRET = randomBytes(32).toString('hex');
const binary = process.env.SB_BIN ?? 'strongbox';
process.env.STRONGBOX_LOCAL_KEYRING_PATH = join(state, 'keyring.json');
process.env.STRONGBOX_BLOB_LOCAL_PATH = join(state, 'blobs');
const children = [];
let host,
  stopping = false;
function stop(code) {
  if (stopping) return;
  stopping = true;
  for (const child of children) child.kill();
  host?.close().catch(() => {});
  process.exitCode = code;
}
for (const signal of ['SIGTERM', 'SIGINT']) process.once(signal, () => stop(0));
function start(command, args, options) {
  const proc = spawn(command, args, { stdio: ['ignore', 'ignore', 'inherit'], ...options });
  children.push(proc);
  proc.on('error', (e) => {
    console.error(e.message);
    stop(1);
  });
  proc.on('exit', () => {
    if (!stopping) {
      console.error('A demo service exited');
      stop(1);
    }
  });
}
async function ready(url) {
  for (let attempt = 0; attempt < 100; attempt++) {
    try {
      const r = await fetch(url, { signal: AbortSignal.timeout(500) });
      await r.body?.cancel();
      if (r.ok) return;
    } catch {}
    await new Promise((ok) => setTimeout(ok, 100));
  }
  throw Error('Service did not start: ' + url);
}
const strongbox = 'http://127.0.0.1:18410';
try {
  const { execFileSync } = await import('node:child_process');
  if (process.env.DC_PACK_BIN)
    execFileSync(process.env.DC_PACK_BIN, [
      '-root',
      join(root, 'examples/dreamcatcher'),
      '-out',
      dir,
      '-stage',
    ]);
  else execFileSync('go', ['run', './examples/dreamcatcher/pack', '-out', dir, '-stage'], { cwd: root });
  provision(process.env.DC_LAB_RUNTIME_LOGIN ?? 'strongbox_api');
  const apiEnv = {
    ...process.env,
    STRONGBOX_MIGRATION_DATABASE_URL: process.env.STRONGBOX_DATABASE_URL,
  };
  start(binary, ['serve', '-addr', '127.0.0.1:18410'], { env: apiEnv });
  await ready(strongbox + '/readyz');
  await collections(strongbox);
  const upstreams = [];
  for (const [i, slug] of Object.keys(profiles).entries()) {
    const port = 18411 + i;
    upstreams.push('http://127.0.0.1:' + port);
    start(process.execPath, ['server.mjs'], {
      cwd: join(dir, slug),
      env: {
        PORT: String(port),
        BIND: '127.0.0.1',
        DC_APP_ID: slug,
        DC_GATEWAY_ORIGIN: 'http://127.0.0.1:18400',
      },
    });
    await ready(upstreams[i] + '/readyz');
  }
  const minted = new Map();
  const subjectToken = async ({ subject }) => {
    let prior = minted.get(subject);
    if (!prior || prior.until < Date.now()) {
      prior = { token: sb('token', subject, '-ttl', '15m'), until: Date.now() + 600000 };
      minted.set(subject, prior);
    }
    return prior.token;
  };
  host = await startHost({ dir, strongboxOrigin: strongbox, subjectToken, upstreams, edgeBind: bind });
  console.log('Readiness notebook  http://127.0.0.1:18401\nSupplier follow-ups http://127.0.0.1:18402');
  if (process.send)
    process.on('message', (m) => {
      // Parent IPC is used only by the contract runner. Nothing exposes these controls over HTTP.
      if (m?.action === 'revoke') host.revoked.add(m.app + '/' + m.user);
      else if (m?.action === 'denyProgram') host.deniedPrograms.add(m.user + '/' + m.program);
      else return;
      process.send('applied');
    });
  process.send?.('ready');
} catch (e) {
  console.error(e.stderr?.toString() || e.message);
  stop(1);
}
