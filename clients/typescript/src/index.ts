// TypeScript client for the Strongbox API.
//
// Wire types come from src/schema.d.ts, generated from internal/api/openapi.json (the contract the
// Go server is tested against); `npm run check-generated` fails when they drift.
//
// Every mutation carries an operation ID (Idempotency-Key), generated per call unless you pass one,
// and reused across this client's retries, so a retry after a lost response returns the original
// result instead of writing twice or failing a version check. Updates are compare-and-swap on the
// record version (If-Match). Retries are bounded and honour Retry-After; every call accepts an
// AbortSignal.

import type { components } from "./schema.d.ts";

type S = components["schemas"];
export type Record_ = S["RecordOut"];
export type Collection = S["CollectionOut"];
export type Blob = S["BlobOut"];
export type UploadSession = S["UploadSession"];
export type Revision = S["Revision"];
export type Grant = S["Grant"];
export type Team = S["Team"];
export type Usage = S["Usage"];
export type Limits = S["Limits"];
export type Receipt = S["Receipt"];
export type Migration = S["Migration"];
export type ContractChange = S["ContractChange"];
export type Problem = S["Problem"];
export type { components, paths } from "./schema.d.ts";

/** Returns a bearer token for the calling identity. Called before every request; cache inside. */
export type TokenProvider = () => string | Promise<string>;

/** An error response from Strongbox (RFC 9457 problem details with a stable code). */
export class StrongboxError extends Error {
  readonly status: number;
  readonly code: string;
  readonly detail: string;
  readonly requestId: string | undefined;
  readonly retryAfter: number | undefined;
  constructor(status: number, code: string, detail: string, requestId?: string, retryAfter?: number) {
    super(`${status} ${code}: ${detail}`);
    this.name = "StrongboxError";
    this.status = status;
    this.code = code;
    this.detail = detail;
    this.requestId = requestId;
    this.retryAfter = retryAfter;
  }
}

/** The record changed since you read it (412) or someone else holds the operation (409). */
export const isConflict = (e: unknown): e is StrongboxError =>
  e instanceof StrongboxError && (e.code === "precondition_failed" || e.code === "conflict");
export const isNotFound = (e: unknown): e is StrongboxError => e instanceof StrongboxError && e.status === 404;

export interface CallOptions {
  signal?: AbortSignal;
  /** Operation ID for a mutation. Reuse it to retry a call whose response you never received. */
  operationId?: string;
}

export interface ClientOptions {
  baseUrl: string;
  auth: TokenProvider;
  /** Act for this user (server-side workloads registered as the app's client only). */
  onBehalfOf?: string;
  /** Attempts per call, including the first (default 4). */
  maxAttempts?: number;
  /** Per-attempt timeout in milliseconds (default 30 000). */
  timeoutMs?: number;
  fetch?: typeof fetch;
}

const RETRY_STATUS = new Set([429, 502, 503, 504]);

const sleep = (ms: number, signal?: AbortSignal) =>
  new Promise<void>((resolve, reject) => {
    if (signal?.aborted) return reject(signal.reason);
    const t = setTimeout(resolve, ms);
    signal?.addEventListener("abort", () => { clearTimeout(t); reject(signal.reason); }, { once: true });
  });

export const newOperationId = () => `op-${crypto.randomUUID()}`;

interface Req {
  method: string;
  path: string;
  query?: Record<string, string | number | boolean | undefined>;
  json?: unknown;
  body?: Uint8Array | ArrayBuffer | globalThis.Blob;
  headers?: Record<string, string>;
  signal?: AbortSignal;
  raw?: boolean;
}

export class Strongbox {
  readonly #opts: Required<Pick<ClientOptions, "maxAttempts" | "timeoutMs">> & ClientOptions;
  readonly #fetch: typeof fetch;

  constructor(opts: ClientOptions) {
    if (!opts.baseUrl) throw new Error("baseUrl is required");
    this.#opts = { maxAttempts: 4, timeoutMs: 30_000, ...opts, baseUrl: opts.baseUrl.replace(/\/+$/, "") };
    this.#fetch = opts.fetch ?? globalThis.fetch.bind(globalThis);
  }

  app(appId: string): App {
    return new App(this, appId);
  }

  limits(o: CallOptions = {}): Promise<Limits> {
    return this.request({ method: "GET", path: "/v1/limits", signal: o.signal });
  }

  /** @internal */
  async request<T>(r: Req): Promise<T> {
    const url = new URL(this.#opts.baseUrl + r.path);
    for (const [k, v] of Object.entries(r.query ?? {})) if (v !== undefined) url.searchParams.set(k, String(v));
    let lastError: unknown;
    for (let attempt = 1; attempt <= this.#opts.maxAttempts; attempt++) {
      const headers: Record<string, string> = { Accept: "application/json", ...r.headers };
      headers.Authorization = `Bearer ${await this.#opts.auth()}`;
      if (this.#opts.onBehalfOf) headers["X-On-Behalf-Of"] = this.#opts.onBehalfOf;
      let body: BodyInit | undefined;
      if (r.json !== undefined) {
        body = JSON.stringify(r.json);
        headers["Content-Type"] = "application/json";
      } else if (r.body !== undefined) {
        body = r.body as BodyInit;
      }
      const timeout = AbortSignal.timeout(this.#opts.timeoutMs);
      const signal = r.signal ? AbortSignal.any([r.signal, timeout]) : timeout;
      let res: Response;
      try {
        res = await this.#fetch(url, { method: r.method, headers, body, signal });
      } catch (e) {
        if (r.signal?.aborted) throw e;
        // Network failure or attempt timeout. Every call is safe to repeat: reads are reads and
        // mutations carry an operation ID.
        lastError = e;
        if (attempt < this.#opts.maxAttempts) {
          await sleep(backoff(attempt), r.signal);
          continue;
        }
        throw e;
      }
      if (res.ok) {
        if (r.raw) return res as T;
        if (res.status === 204) return undefined as T;
        return (await res.json()) as T;
      }
      const problem = (await res.json().catch(() => ({}))) as Partial<Problem>;
      const retryAfter = Number(res.headers.get("Retry-After")) || undefined;
      const err = new StrongboxError(res.status, problem.code ?? "error", problem.detail ?? res.statusText,
        problem.request_id ?? undefined, retryAfter);
      const retryable = RETRY_STATUS.has(res.status) || (res.status === 409 && err.code === "operation_in_progress");
      if (!retryable || attempt === this.#opts.maxAttempts) throw err;
      lastError = err;
      await sleep(retryAfter ? Math.min(retryAfter * 1000, 10_000) : backoff(attempt), r.signal);
    }
    throw lastError;
  }
}

const backoff = (attempt: number) => Math.min(5_000, 200 * 2 ** (attempt - 1)) * (0.5 + Math.random() / 2);

const enc = encodeURIComponent;
const etag = (v: number) => `"v${v}"`;

export interface RecordInput {
  data: Record<string, unknown>;
  marking?: string;
  /** private (default) | team | app */
  visibility?: "private" | "team" | "app";
  team_id?: string;
}

export interface BlobOptions extends CallOptions {
  marking?: string;
  contentType?: string;
  filename?: string;
  metadata?: Record<string, unknown>;
  visibility?: "private" | "team" | "app";
  teamId?: string;
}

export class App {
  readonly #c: Strongbox;
  readonly base: string;
  readonly id: string;
  constructor(c: Strongbox, id: string) {
    this.#c = c;
    this.id = id;
    this.base = `/v1/apps/${enc(id)}`;
  }

  #req<T>(r: Req): Promise<T> {
    return this.#c.request<T>(r);
  }

  #mut(o: CallOptions, extra: Record<string, string> = {}) {
    return { ...extra, "Idempotency-Key": o.operationId ?? newOperationId() };
  }

  #rec(coll: string, id: string) {
    return `${this.base}/collections/${enc(coll)}/records/${enc(id)}`;
  }

  info(o: CallOptions = {}) {
    return this.#req<S["AppInfo"]>({ method: "GET", path: this.base, signal: o.signal });
  }

  usage(o: CallOptions = {}) {
    return this.#req<Usage>({ method: "GET", path: `${this.base}/usage`, signal: o.signal });
  }

  /** Status of an earlier mutation by operation ID: succeeded (with the version written), pending or not_found. */
  operation(opId: string, o: CallOptions = {}) {
    return this.#req<Receipt>({ method: "GET", path: `${this.base}/operations/${enc(opId)}`, signal: o.signal });
  }

  // ---- teams ----
  createTeam(name: string, o: CallOptions = {}) {
    return this.#req<Team>({ method: "POST", path: `${this.base}/teams`, json: { name }, signal: o.signal });
  }
  setTeamMember(team: string, subject: string, role: "viewer" | "editor" | "admin", o: CallOptions = {}) {
    return this.#req<unknown>({ method: "PUT", path: `${this.base}/teams/${enc(team)}/members/${enc(subject)}`, json: { role }, signal: o.signal });
  }

  // ---- collections ----
  createCollection(spec: S["CollectionIn"], o: CallOptions = {}) {
    return this.#req<Collection>({ method: "POST", path: `${this.base}/collections`, json: spec, headers: this.#mut(o), signal: o.signal });
  }
  getCollection(name: string, o: CallOptions = {}) {
    return this.#req<Collection>({ method: "GET", path: `${this.base}/collections/${enc(name)}`, signal: o.signal });
  }
  async listCollections(o: CallOptions = {}) {
    return (await this.#req<S["CollectionList"]>({ method: "GET", path: `${this.base}/collections`, signal: o.signal })).items;
  }
  /** Stage a new contract version; `immediate` says whether it took effect or a migration started. */
  changeContract(name: string, contract: S["ContractIn"], o: CallOptions = {}) {
    return this.#req<ContractChange>({ method: "PUT", path: `${this.base}/collections/${enc(name)}/contract`, json: contract,
      headers: this.#mut(o), signal: o.signal });
  }
  getMigration(name: string, id: string, o: CallOptions = {}) {
    return this.#req<Migration>({ method: "GET", path: `${this.base}/collections/${enc(name)}/migrations/${enc(id)}`, signal: o.signal });
  }

  // ---- records ----
  createRecord(coll: string, input: RecordInput, o: CallOptions = {}) {
    return this.#req<Record_>({ method: "POST", path: `${this.base}/collections/${enc(coll)}/records`, json: input,
      headers: this.#mut(o), signal: o.signal });
  }
  getRecord(coll: string, id: string, o: CallOptions = {}) {
    return this.#req<Record_>({ method: "GET", path: this.#rec(coll, id), signal: o.signal });
  }
  /** Replace a record's data if it is still at expectedVersion (compare-and-swap). */
  updateRecord(coll: string, id: string, expectedVersion: number, input: Omit<RecordInput, "visibility" | "team_id">, o: CallOptions = {}) {
    return this.#req<Record_>({ method: "PUT", path: this.#rec(coll, id), json: input,
      headers: this.#mut(o, { "If-Match": etag(expectedVersion) }), signal: o.signal });
  }
  /**
   * Read-modify-write with conflict recovery: reads the record, applies change, and writes with
   * compare-and-swap; if someone else wrote first, re-reads and re-applies (up to `attempts`).
   * `change` must be a pure function of the record it is given.
   */
  async mutate(coll: string, id: string, change: (data: Record<string, unknown>, rec: Record_) => Record<string, unknown>,
    o: CallOptions & { attempts?: number } = {}): Promise<Record_> {
    for (let i = 1; ; i++) {
      const cur = await this.getRecord(coll, id, o);
      const data = change(structuredClone((cur.data ?? {}) as Record<string, unknown>), cur);
      try {
        // A fresh operation ID per attempt: each attempt is a different write.
        return await this.updateRecord(coll, id, cur.version, { data }, { signal: o.signal });
      } catch (e) {
        if (!isConflict(e) || i >= (o.attempts ?? 5)) throw e;
      }
    }
  }
  deleteRecord(coll: string, id: string, opts: CallOptions & { expectedVersion?: number; purge?: boolean } = {}) {
    const extra: Record<string, string> = opts.expectedVersion ? { "If-Match": etag(opts.expectedVersion) } : {};
    return this.#req<void>({ method: "DELETE", path: this.#rec(coll, id), query: { purge: opts.purge },
      headers: this.#mut(opts, extra), signal: opts.signal });
  }
  query(coll: string, filters: Record<string, unknown> = {}, opts: CallOptions & { limit?: number; cursor?: string } = {}) {
    return this.#req<S["QueryOut"]>({ method: "POST", path: `${this.base}/collections/${enc(coll)}/query`,
      json: { filters, limit: opts.limit, cursor: opts.cursor }, signal: opts.signal });
  }
  /** Every matching record, following cursors. */
  async *queryAll(coll: string, filters: Record<string, unknown> = {}, o: CallOptions = {}): AsyncGenerator<Record_> {
    let cursor: string | undefined;
    do {
      const page = await this.query(coll, filters, { ...o, limit: 200, cursor });
      yield* page.items;
      cursor = page.next_cursor ?? undefined;
    } while (cursor);
  }
  history(coll: string, id: string, opts: CallOptions & { limit?: number; before?: number } = {}) {
    return this.#req<S["HistoryOut"]>({ method: "GET", path: `${this.#rec(coll, id)}/history`,
      query: { limit: opts.limit, before: opts.before }, signal: opts.signal });
  }
  revision(coll: string, id: string, version: number, o: CallOptions = {}) {
    return this.#req<Record_>({ method: "GET", path: `${this.#rec(coll, id)}/history/${version}`, signal: o.signal });
  }
  /** Undo: write version `version`'s content as a new version, if the record is at currentVersion. */
  restore(coll: string, id: string, version: number, currentVersion: number, o: CallOptions = {}) {
    return this.#req<Record_>({ method: "POST", path: `${this.#rec(coll, id)}/restore`, json: { version },
      headers: this.#mut(o, { "If-Match": etag(currentVersion) }), signal: o.signal });
  }

  // ---- sharing ----
  share(coll: string, id: string, visibility: "private" | "team" | "app", teamId?: string, o: CallOptions = {}) {
    return this.#req<S["SharingOut"]>({ method: "PUT", path: `${this.#rec(coll, id)}/sharing`,
      json: { visibility, team_id: teamId }, signal: o.signal });
  }
  grant(coll: string, id: string, g: S["GrantIn"], o: CallOptions = {}) {
    return this.#req<Grant>({ method: "POST", path: `${this.#rec(coll, id)}/grants`, json: g, signal: o.signal });
  }
  revoke(coll: string, id: string, grantId: string, o: CallOptions = {}) {
    return this.#req<void>({ method: "DELETE", path: `${this.#rec(coll, id)}/grants/${enc(grantId)}`, signal: o.signal });
  }

  // ---- blobs ----
  /** One-request upload, up to limits().max_single_upload_bytes. Use putLargeBlob beyond that. */
  putBlob(data: Uint8Array | ArrayBuffer | globalThis.Blob, o: BlobOptions = {}) {
    const headers: Record<string, string> = this.#mut(o, {
      "Content-Type": o.contentType ?? "application/octet-stream",
      "X-Strongbox-Marking": o.marking ?? "UNCONTROLLED",
    });
    if (o.filename) headers["X-Strongbox-Filename"] = enc(o.filename);
    if (o.metadata) headers["X-Strongbox-Metadata"] = base64url(new TextEncoder().encode(JSON.stringify(o.metadata)));
    if (o.visibility) headers["X-Strongbox-Visibility"] = o.visibility;
    if (o.teamId) headers["X-Strongbox-Team"] = o.teamId;
    return this.#req<Blob>({ method: "POST", path: `${this.base}/blobs`, body: data, headers, signal: o.signal });
  }
  getBlob(id: string, o: CallOptions = {}) {
    return this.#req<Blob>({ method: "GET", path: `${this.base}/blobs/${enc(id)}`, signal: o.signal });
  }
  /** The decrypted content as a stream (the Response body). */
  async openBlob(id: string, o: CallOptions = {}): Promise<Response> {
    return this.#req<Response>({ method: "GET", path: `${this.base}/blobs/${enc(id)}/content`, raw: true, signal: o.signal });
  }
  async readBlob(id: string, o: CallOptions = {}): Promise<Uint8Array> {
    return new Uint8Array(await (await this.openBlob(id, o)).arrayBuffer());
  }
  deleteBlob(id: string, opts: CallOptions & { shred?: boolean } = {}) {
    return this.#req<void>({ method: "DELETE", path: `${this.base}/blobs/${enc(id)}`, query: { shred: opts.shred },
      headers: this.#mut(opts), signal: opts.signal });
  }

  createUpload(size: number, o: BlobOptions = {}) {
    return this.#req<UploadSession>({ method: "POST", path: `${this.base}/uploads`, headers: this.#mut(o), signal: o.signal,
      json: { size_bytes: size, marking: o.marking ?? "UNCONTROLLED", content_type: o.contentType, filename: o.filename,
        metadata: o.metadata, visibility: o.visibility, team_id: o.teamId } });
  }
  getUpload(id: string, o: CallOptions = {}) {
    return this.#req<UploadSession>({ method: "GET", path: `${this.base}/uploads/${enc(id)}`, signal: o.signal });
  }
  uploadPart(id: string, n: number, data: Uint8Array, o: CallOptions = {}) {
    return this.#req<S["PartOut"]>({ method: "PUT", path: `${this.base}/uploads/${enc(id)}/parts/${n}`, body: data,
      headers: { "Content-Type": "application/octet-stream" }, signal: o.signal });
  }
  completeUpload(id: string, o: CallOptions = {}) {
    return this.#req<Blob>({ method: "POST", path: `${this.base}/uploads/${enc(id)}/complete`, headers: this.#mut(o), signal: o.signal });
  }
  abortUpload(id: string, o: CallOptions = {}) {
    return this.#req<void>({ method: "DELETE", path: `${this.base}/uploads/${enc(id)}`, signal: o.signal });
  }
  /**
   * Upload `data` through an upload session, `parallel` parts at a time. Pass `resume` (an upload
   * ID) to send only the parts a previous attempt did not.
   */
  async putLargeBlob(data: Uint8Array, o: BlobOptions & { parallel?: number; resume?: string } = {}): Promise<Blob> {
    const sess = o.resume ? await this.getUpload(o.resume, o) : await this.createUpload(data.byteLength, o);
    const have = new Set(sess.received_parts);
    const todo = Array.from({ length: sess.part_count }, (_, i) => i + 1).filter((n) => !have.has(n));
    const workers = Array.from({ length: Math.max(1, Math.min(o.parallel ?? 4, 8)) }, async () => {
      for (let n = todo.shift(); n !== undefined; n = todo.shift()) {
        const start = (n - 1) * sess.part_size;
        await this.uploadPart(sess.upload_id, n, data.subarray(start, Math.min(start + sess.part_size, sess.size_bytes)), o);
      }
    });
    await Promise.all(workers);
    return this.completeUpload(sess.upload_id, { signal: o.signal, operationId: `complete-${sess.upload_id}` });
  }
}

function base64url(b: Uint8Array): string {
  let s = "";
  for (const x of b) s += String.fromCharCode(x);
  return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

// ---- credentials -----------------------------------------------------------------------------------

const inBrowser = () => typeof (globalThis as { window?: unknown }).window !== "undefined";

/**
 * A workload identity token from the GCP metadata server (Cloud Run, GKE, GCE), cached until shortly
 * before it expires. Server-only: it throws in a browser, so a workload credential cannot be
 * shipped to users by accident.
 */
export function gcpWorkloadIdentity(audience: string, f: typeof fetch = globalThis.fetch): TokenProvider {
  if (inBrowser()) throw new Error("gcpWorkloadIdentity is server-only; browsers must use userToken()");
  let cached: { token: string; exp: number } | undefined;
  return async () => {
    if (cached && cached.exp - 60_000 > Date.now()) return cached.token;
    const url = `http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/identity?audience=${enc(audience)}&format=full`;
    const res = await f(url, { headers: { "Metadata-Flavor": "Google" } });
    if (!res.ok) throw new Error(`metadata server: ${res.status}`);
    const token = await res.text();
    const payload = JSON.parse(atob(token.split(".")[1]!.replace(/-/g, "+").replace(/_/g, "/"))) as { exp: number };
    cached = { token, exp: payload.exp * 1000 };
    return token;
  };
}

/** A user's token from your sign-in library (browser or server). Strongbox verifies it. */
export const userToken = (get: () => string | Promise<string>): TokenProvider => get;

/** A fixed token (tests, local development). */
export const staticToken = (token: string): TokenProvider => () => token;
