// Mount this handler at the trusted Dreamcatcher gateway. Uploaded backends can
// present a runtime token, but cannot choose a Strongbox scope, subject or route.
import { createHash } from 'node:crypto';
import { readFile } from 'node:fs/promises';

export const profiles = JSON.parse(await readFile(new URL('../profiles.json', import.meta.url)));
export const fileLimit = 32 * 1024; // source edge caps its entire request at 64 KiB
const smallKey = (value) => typeof value === 'string' && /^[A-Za-z0-9_-]{1,80}$/.test(value);
const own = (obj, key) => (Object.hasOwn(obj, key) ? obj[key] : undefined);
export class RequestError extends Error {
  constructor(status, code) {
    super(code);
    this.status = status;
    this.code = code;
  }
}
export function origin(raw) {
  const u = new URL(raw);
  if (
    u.origin !== u.href.replace(/\/$/, '') ||
    !(
      u.protocol === 'https:' ||
      (u.protocol === 'http:' && ['127.0.0.1', 'localhost', '[::1]'].includes(u.hostname))
    )
  )
    throw Error('Expected HTTPS origin or local loopback');
  return u.origin;
}
export async function bounded(stream, limit) {
  let size = 0;
  const chunks = [];
  for await (const bytes of stream) {
    size += bytes.length;
    if (size > limit) throw new RequestError(413, 'size_limit');
    chunks.push(bytes);
  }
  return Buffer.concat(chunks);
}
export async function jsonInput(req) {
  const bytes = await bounded(req, 65536);
  try {
    const value = JSON.parse(bytes);
    if (!value || Array.isArray(value) || typeof value !== 'object') throw Error();
    return value;
  } catch {
    throw new RequestError(400, 'invalid_json');
  }
}
export function json(res, status, value) {
  res.writeHead(status, {
    'content-type': 'application/json',
    'cache-control': 'no-store',
    'x-content-type-options': 'nosniff',
  });
  res.end(JSON.stringify(value));
}
export function failure(res, e) {
  json(res, e instanceof RequestError ? e.status : 503, {
    code: e instanceof RequestError ? e.code : 'service_unavailable',
  });
}
export async function httpCall(
  url,
  token,
  { method = 'GET', body, headers = {}, limit = 1 << 20, raw = false } = {},
) {
  const reply = await fetch(url, {
    method,
    headers: { authorization: 'Bearer ' + token, ...headers },
    body,
    redirect: 'error',
    signal: AbortSignal.timeout(12000),
  });
  if (!reply.ok) {
    const bytes = await bounded(reply.body, 32768);
    let code = 'upstream_denied';
    try {
      const v = JSON.parse(bytes);
      if (/^[a-z_]{1,64}$/.test(v.code ?? '')) code = v.code;
    } catch {}
    throw new RequestError(reply.status, code);
  }
  if (reply.status === 204) return null;
  const bytes = await bounded(reply.body, limit);
  return raw ? bytes : JSON.parse(bytes);
}
const postJSON = (body, headers = {}) => ({
  method: 'POST',
  body: JSON.stringify(body),
  headers: { 'content-type': 'application/json', ...headers },
});
function project(record) {
  return {
    id: record.id,
    version: record.version,
    note: record.data.note,
    status: record.data.status,
    has_file: !!record.attachment_id,
  };
}
function attachment(input) {
  if (
    !input ||
    typeof input.name !== 'string' ||
    !/^[^/\\\x00-\x1f\x7f]{1,100}$/u.test(input.name) ||
    typeof input.base64 !== 'string' ||
    input.base64.length > 4 * Math.ceil(fileLimit / 3)
  )
    throw new RequestError(422, 'invalid_file');
  const bytes = Buffer.from(input.base64, 'base64');
  if (bytes.length > fileLimit || bytes.toString('base64') !== input.base64)
    throw new RequestError(422, 'invalid_file');
  return bytes;
}

export function storageHandler({
  gatewayOrigin,
  strongboxOrigin,
  bindings,
  subjects,
  subjectToken,
  invokerToken,
}) {
  const dc = origin(gatewayOrigin),
    sb = origin(strongboxOrigin);
  for (const b of Object.values(bindings)) {
    if (
      !own(profiles, b.profile) ||
      !b.submissionId ||
      !b.marking ||
      !/^[a-z][a-z0-9-]{1,39}$/.test(b.strongboxApp)
    )
      throw Error('Invalid storage binding');
  }
  if (new Set(Object.values(bindings).map((b) => b.strongboxApp)).size !== Object.keys(bindings).length)
    throw Error('Each Dreamcatcher app needs its own Strongbox scope');
  return async (req, res) => {
    try {
      const match = /^\/api\/v2\/runtime\/([A-Za-z0-9-]{1,80})\/storage$/.exec(req.url);
      const binding = match && own(bindings, match[1]);
      if (!binding || req.method !== 'POST') throw new RequestError(404, 'not_found');
      const token = /^Bearer ([^\s,]{1,4096})$/.exec(req.headers.authorization ?? '')?.[1];
      if (!token) throw new RequestError(401, 'unauthenticated');
      const runtime = dc + '/api/v2/runtime/' + match[1],
        profile = profiles[binding.profile];
      const context = await httpCall(runtime + '/context', token);
      if (
        context.app_id !== match[1] ||
        context.submission_id !== binding.submissionId ||
        !context.queries?.includes(profile.query)
      )
        throw new RequestError(403, 'release_not_bound');
      const subject = own(subjects, context.user?.id);
      if (!subject) throw new RequestError(403, 'subject_not_bound');
      const input = await jsonInput(req);
      if (
        !smallKey(input.program_id) ||
        !smallKey(input.row_id) ||
        !['list', 'save', 'download'].includes(input.action)
      )
        throw new RequestError(422, 'invalid_input');
      // Query entitlements can change independently of Strongbox sharing. Only stable
      // keys and the user's own note/status are written to storage.
      const page = await httpCall(
        runtime + '/queries',
        token,
        postJSON({ reference: profile.query, parameters: { program_id: input.program_id } }),
      );
      if (!page.rows?.some((r) => r[profile.key] === input.row_id && r.program_id === input.program_id))
        throw new RequestError(404, 'not_found');
      const fields = new Set([
        'action',
        'program_id',
        'row_id',
        ...(input.action === 'save'
          ? ['id', 'expected_version', 'note', 'status', 'operation_id', 'file']
          : input.action === 'list'
            ? ['cursor']
            : ['id']),
      ]);
      if (Object.keys(input).some((k) => !fields.has(k))) throw new RequestError(422, 'unknown_field');
      const credential = await subjectToken({ token, subject, context });
      const iam = invokerToken ? await invokerToken() : undefined;
      const storage = (path, options = {}) =>
        httpCall(sb + path, credential, {
          ...options,
          headers: {
            ...options.headers,
            ...(iam ? { 'X-Serverless-Authorization': 'Bearer ' + iam } : {}),
          },
        });
      const identity = await storage('/v1/whoami');
      if (identity.subject !== subject || identity.kind !== 'user' || identity.actor)
        throw new RequestError(403, 'subject_mismatch');
      const app = '/v1/apps/' + binding.strongboxApp,
        collection = app + '/collections/' + profile.collection;
      const recordBase = collection + '/records';
      const filters = { program_id: input.program_id, row_id: input.row_id };
      if (input.action === 'list') {
        if (input.cursor != null && (typeof input.cursor !== 'string' || input.cursor.length > 2048))
          throw new RequestError(422, 'invalid_cursor');
        const result = await storage(
          collection + '/query',
          postJSON({ filters, limit: 20, cursor: input.cursor ?? null }),
        );
        json(res, 200, { items: result.items.map(project), next_cursor: result.next_cursor });
        return;
      }
      let current;
      if (input.id !== undefined || input.action === 'download') {
        if (!/^rec_[a-f0-9]{32}$/.test(input.id ?? '')) throw new RequestError(422, 'invalid_record');
        current = await storage(recordBase + '/' + input.id);
        if (current.data?.program_id !== input.program_id || current.data?.row_id !== input.row_id)
          throw new RequestError(404, 'not_found');
      }
      if (input.action === 'download') {
        if (!profile.files || !current.attachment_id) throw new RequestError(404, 'not_found');
        const bytes = await storage(app + '/blobs/' + current.attachment_id + '/content', {
          raw: true,
          limit: fileLimit,
        });
        res
          .writeHead(200, {
            'content-type': 'application/octet-stream',
            'cache-control': 'no-store',
            'x-content-type-options': 'nosniff',
          })
          .end(bytes);
        return;
      }
      if (
        typeof input.note !== 'string' ||
        !input.note.trim() ||
        input.note.length > 1500 ||
        !profile.statuses.includes(input.status) ||
        typeof input.operation_id !== 'string' ||
        !/^[A-Za-z0-9_-]{8,80}$/.test(input.operation_id) ||
        (current
          ? !(Number.isInteger(input.expected_version) && input.expected_version > 0)
          : input.expected_version !== undefined) ||
        (input.file !== undefined && (!profile.files || current))
      )
        throw new RequestError(422, 'invalid_save');
      const payload = { data: { ...filters, note: input.note, status: input.status } };
      const opts = { 'Idempotency-Key': input.operation_id };
      if (current) opts['If-Match'] = '"v' + input.expected_version + '"';
      else {
        payload.visibility = profile.visibility;
        payload.marking = binding.marking;
      }
      if (input.file !== undefined) {
        const bytes = attachment(input.file);
        // Binding the upload to the logical save avoids conflating retries in different
        // rows. Strongbox checks that a retried upload has the same metadata and bytes.
        const fileOp =
          'file-' +
          createHash('sha256')
            .update(JSON.stringify([input.operation_id, filters]))
            .digest('hex');
        const blob = await storage(app + '/blobs', {
          method: 'POST',
          body: bytes,
          headers: {
            'content-type': 'application/octet-stream',
            'Idempotency-Key': fileOp,
            'X-Strongbox-Marking': binding.marking,
            'X-Strongbox-Visibility': profile.visibility,
            'X-Strongbox-Filename': encodeURIComponent(input.file.name),
          },
        });
        payload.attachment_id = blob.id;
      }
      const options = postJSON(payload, opts);
      options.method = current ? 'PUT' : 'POST';
      try {
        const saved = await storage(recordBase + (current ? '/' + current.id : ''), options);
        json(res, current ? 200 : 201, project(saved));
      } catch (e) {
        // A final rejection leaves no committed record. A timeout can hide a successful
        // commit. Only clean up definite rejections; the database also protects linked files.
        if (
          payload.attachment_id &&
          e instanceof RequestError &&
          ([403, 404, 412, 422, 507].includes(e.status) || e.code === 'idempotency_key_reused')
        ) {
          try {
            await storage(app + '/blobs/' + payload.attachment_id, {
              method: 'DELETE',
              headers: { 'Idempotency-Key': 'discard-' + payload.attachment_id },
            });
          } catch (cleanup) {
            if (cleanup.code !== 'conflict') throw cleanup;
          }
        }
        throw e;
      }
    } catch (e) {
      failure(res, e);
    }
  };
}
