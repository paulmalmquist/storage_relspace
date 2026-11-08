import { execFileSync } from 'node:child_process';
import { profiles } from '../host/storage.mjs';
import { provisionCollection } from '../host/collections.mjs';
import { subjects } from './fixtures.mjs';
export const sb = (...args) =>
  execFileSync(process.env.SB_BIN ?? 'strongbox', args, {
    encoding: 'utf8',
    stdio: ['ignore', 'pipe', 'pipe'],
  }).trim();
export function provision(login) {
  sb('init', '-bootstrap-roles', '-runtime-login', login);
  const admin = 'owner@fixture.test';
  sb('principal', 'put', admin, '-scope', 'collections:admin', '-scope', 'records:read');
  for (const subject of Object.values(subjects))
    sb(
      'principal',
      'put',
      subject,
      '-scope',
      'records:read',
      '-scope',
      'records:write',
      '-scope',
      'blobs:read',
      '-scope',
      'blobs:write',
      '-scope',
      'blobs:delete',
    );
  for (const app of ['readiness', 'supplier']) {
    try {
      sb('admin', 'app', 'create', app + ':dev', '-admin', admin);
    } catch (e) {
      if (!String(e.stderr).includes('SQLSTATE 23505')) throw e;
    }
    for (const user of Object.values(subjects))
      sb('admin', 'member', 'set', app + ':dev', user, 'editor');
  }
}
export async function collections(strongbox) {
  const token = sb('token', 'owner@fixture.test');
  for (const [profile, p] of Object.entries(profiles))
    await provisionCollection(strongbox, token, {
      strongboxApp: p.files ? 'supplier' : 'readiness',
      profile,
      marking: 'UNCONTROLLED',
    });
}
