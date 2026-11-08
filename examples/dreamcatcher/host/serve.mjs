// Run alongside the operator-owned Dreamcatcher gateway. Route only
// /api/v2/runtime/{app}/storage here. Its existing context/query endpoints remain authoritative.
import http from 'node:http';
import { readFile } from 'node:fs/promises';
import { bounded, RequestError, storageHandler } from './storage.mjs';
import { pathToFileURL } from 'node:url';
export function exchangeCredential({ url, clientId, clientSecret, audience }, fetcher = fetch) {
  const endpoint = new URL(url);
  if (
    endpoint.protocol !== 'https:' ||
    endpoint.username ||
    endpoint.password ||
    endpoint.hash ||
    endpoint.search ||
    !clientId ||
    !clientSecret ||
    !audience
  )
    throw Error('Configure a trusted HTTPS token exchange, audience and service client');
  const idType = 'urn:ietf:params:oauth:token-type:id_token';
  const basic = Buffer.from(
    encodeURIComponent(clientId) + ':' + encodeURIComponent(clientSecret),
  ).toString('base64');
  return async ({ token }) => {
    const body = new URLSearchParams({
      grant_type: 'urn:ietf:params:oauth:grant-type:token-exchange',
      subject_token: token,
      subject_token_type: 'urn:ietf:params:oauth:token-type:access_token',
      requested_token_type: idType,
      audience,
    });
    const r = await fetcher(endpoint, {
      method: 'POST',
      body,
      headers: { authorization: 'Basic ' + basic },
      redirect: 'error',
      signal: AbortSignal.timeout(4000),
    });
    if (!r.ok) {
      await r.body?.cancel();
      throw new RequestError(
        r.status === 400 || r.status === 403 ? 403 : 503,
        'identity_exchange_failed',
      );
    }
    const value = JSON.parse(await bounded(r.body, 32768));
    if (
      value.issued_token_type !== idType ||
      typeof value.access_token !== 'string' ||
      !value.access_token
    )
      throw Error('Identity provider returned an invalid token response');
    return value.access_token;
  };
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  const env = process.env,
    config = JSON.parse(await readFile(env.DC_STORAGE_BINDINGS, 'utf8'));
  const handler = storageHandler({
    gatewayOrigin: env.DC_GATEWAY_ORIGIN,
    strongboxOrigin: env.STRONGBOX_URL,
    ...config,
    subjectToken: exchangeCredential({
      url: env.DC_TOKEN_EXCHANGE_URL,
      clientId: env.DC_TOKEN_CLIENT_ID,
      clientSecret: env.DC_TOKEN_CLIENT_SECRET,
      audience: env.STRONGBOX_AUDIENCE,
    }),
  });
  const server = http.createServer(handler);
  server.requestTimeout = 25000;
  server.headersTimeout = 10000;
  server.listen(Number(env.PORT ?? 8099), env.BIND ?? '127.0.0.1');
}
