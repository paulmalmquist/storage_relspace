// Operator provisioning via the Strongbox HTTP API. This module is outside the source ZIPs.
import { isDeepStrictEqual } from 'node:util';
import { readFile } from 'node:fs/promises';
import { pathToFileURL } from 'node:url';
import { profiles, httpCall, origin } from './storage.mjs';
export async function provisionCollection(strongbox, token, { strongboxApp, profile, marking }) {
  if (!/^[a-z][a-z0-9_-]{1,62}$/.test(strongboxApp) || !Object.hasOwn(profiles, profile) || !marking)
    throw Error('Invalid binding');
  const p = profiles[profile],
    base = origin(strongbox) + '/v1/apps/' + strongboxApp + '/collections';
  const json_schema = {
    type: 'object',
    additionalProperties: false,
    required: ['program_id', 'row_id', 'note', 'status'],
    properties: {
      program_id: { type: 'string', maxLength: 80 },
      row_id: { type: 'string', maxLength: 80 },
      note: { type: 'string', minLength: 1, maxLength: 1500 },
      status: { enum: p.statuses },
    },
  };
  const spec = {
    name: p.collection,
    encrypted: true,
    indexed_fields: ['program_id', 'row_id'],
    unique_fields: [],
    json_schema,
    marking,
  };
  const target = base + '/' + p.collection;
  let existing;
  try {
    existing = await httpCall(target, token);
  } catch (e) {
    if (e.status !== 404) throw e;
    try {
      await httpCall(base, token, {
        method: 'POST',
        headers: {
          'content-type': 'application/json',
          'Idempotency-Key': 'create-collection-' + p.collection,
        },
        body: JSON.stringify(spec),
      });
    } catch (err) {
      if (err.code !== 'conflict') throw err;
    }
    existing = await httpCall(target, token);
  }
  if (
    !existing.encrypted ||
    existing.marking !== marking ||
    existing.pending_version != null ||
    !isDeepStrictEqual(existing.json_schema, json_schema) ||
    !isDeepStrictEqual([...existing.indexed_fields].sort(), spec.indexed_fields) ||
    existing.unique_fields.length !== 0
  ) {
    throw Error('Collection contract mismatch in ' + strongboxApp + '/' + p.collection);
  }
}
if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  const env = process.env;
  const { bindings } = JSON.parse(await readFile(env.DC_STORAGE_BINDINGS));
  if (!env.STRONGBOX_OPERATOR_TOKEN) throw Error('Supply a short-lived operator token');
  for (const binding of Object.values(bindings))
    await provisionCollection(env.STRONGBOX_URL, env.STRONGBOX_OPERATOR_TOKEN, binding);
}
