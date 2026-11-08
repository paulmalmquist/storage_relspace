// Register the two fixtures and submit source to a disposable local Dreamcatcher.
import { readFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import { createHash } from 'node:crypto';
import { profiles } from '../host/storage.mjs';
const url = new URL(process.argv[2] ?? 'http://127.0.0.1:8000');
if (url.protocol !== 'http:' || url.hostname !== '127.0.0.1' || url.origin + '/' !== url.href)
  throw Error('Use the loopback origin of a disposable local Dreamcatcher');
const dir = resolve(process.argv[3] ?? 'dist/dreamcatcher');
const headers = {};
async function post(path, body) {
  const form = body instanceof FormData;
  const r = await fetch(url.origin + path, {
    method: 'POST',
    headers: { ...headers, ...(form ? {} : { 'content-type': 'application/json' }) },
    body: form ? body : JSON.stringify(body),
    redirect: 'error',
    signal: AbortSignal.timeout(10000),
  });
  if (!r.ok)
    throw Error(
      'Upload contract ' + path + ' returned ' + r.status + ': ' + (await r.text()).slice(0, 300),
    );
  if (path === '/api/login') {
    const c = r.headers.getSetCookie().find((s) => s.startsWith('dc_session='));
    if (!c) throw Error('Missing local session');
    headers.cookie = c.split(';')[0];
  }
  return r.json();
}
const login = await post('/api/login', {
  email: 'builder@demo.local',
  password: process.env.DC_DEMO_PASSWORD ?? 'Dreamcatcher-local-1!',
});
headers['x-csrf-token'] = login.csrf;
const results = [];
for (const [slug, p] of Object.entries(profiles)) {
  const bytes = await readFile(resolve(dir, slug + '.zip'));
  const app = await post('/api/v2/apps', {
    name: p.title,
    category: p.category,
    description: 'Synthetic Strongbox integration fixture',
    classification: 'internal',
  });
  const data = new FormData();
  data.append('file', new Blob([bytes], { type: 'application/zip' }), slug + '.zip');
  const submission = await post('/api/v2/apps/' + app.id + '/submissions', data);
  if (submission.status !== 'queued' || !submission.job_id || submission.app_id !== app.id)
    throw Error('Missing queued build receipt');
  results.push({
    fixture: slug,
    app_id: app.id,
    submission_id: submission.id,
    job_id: submission.job_id,
    status: submission.status,
    source_digest: submission.source_digest,
    archive_sha256: createHash('sha256').update(bytes).digest('hex'),
  });
}
console.log(JSON.stringify(results, null, 2));
