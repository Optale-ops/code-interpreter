/**
 * In-process harness for route-level auth tests: the real `apiKeyAuth` and
 * service router behind an Express app, with an in-memory stand-in for
 * Redis/BullMQ and a stub file server on a loopback port. No Redis, MinIO or
 * sandbox is needed, so the suites stay CI-safe.
 *
 * `installRouteHarness()` must run before anything imports `../queue`: it
 * registers the queue mock and only then loads the routers. That ordering is
 * why the router modules are imported dynamically here.
 */
import { mock, spyOn } from 'bun:test';
import { createHash, createPrivateKey, createPublicKey, sign as cryptoSign } from 'crypto';
import { createServer } from 'http';
import express from 'express';
import type { KeyObject } from 'crypto';
import type { IncomingMessage, Server } from 'http';
import type { AddressInfo } from 'net';

type StoreEntry = { value: string; ttl?: number };

export type CapturedLog = { level: string; message: string; meta?: unknown };
export type CapturedPut = { url: string; headers: Record<string, string>; bytes: number };
export type CapturedFileServerCall = { method: string; url: string; headers: Record<string, string> };
export type DeleteHandler = (req: IncomingMessage, key: string) => { status: number; body: unknown };

/** Fixed Ed25519 seed so token bytes are reproducible across runs and trees. */
const SIGNING_SEED = Buffer.alloc(32, 7);
const PKCS8_ED25519_PREFIX = Buffer.from('302e020100300506032b657004220420', 'hex');

export const TEST_KID = 'parity-kid';
export const INTERNAL_TOKEN = 'internal-service-token-for-route-harness-0001';
export const EGRESS_SECRET = 'egress-grant-secret-for-route-harness-000000001';

export function testSigningKey(seed: Buffer = SIGNING_SEED): KeyObject {
  return createPrivateKey({
    key: Buffer.concat([PKCS8_ED25519_PREFIX, seed]),
    format: 'der',
    type: 'pkcs8',
  });
}

export function jwksFor(entries: Array<{ kid: string; key: KeyObject; tenants?: string[] }>): string {
  return JSON.stringify({
    keys: entries.map(entry => {
      const jwk = createPublicKey(entry.key).export({ format: 'jwk' });
      return {
        kty: jwk.kty,
        crv: jwk.crv,
        x: jwk.x,
        kid: entry.kid,
        alg: 'EdDSA',
        ...(entry.tenants ? { tenants: entry.tenants } : {}),
      };
    }),
  });
}

export function signTestJwt(
  claims: Record<string, unknown>,
  key: KeyObject = testSigningKey(),
  kid = TEST_KID,
): string {
  const header = { alg: 'EdDSA', typ: 'JWT', kid };
  const signingInput = `${Buffer.from(JSON.stringify(header)).toString('base64url')}.${Buffer.from(
    JSON.stringify(claims),
  ).toString('base64url')}`;
  return `${signingInput}.${cryptoSign(null, Buffer.from(signingInput), key).toString('base64url')}`;
}

export function configureJwtEnv(jwksJson: string): void {
  process.env.CODEAPI_AUTH_PROVIDER = 'librechat-jwt';
  process.env.CODEAPI_JWT_ISSUER = 'librechat';
  process.env.CODEAPI_JWT_AUDIENCE = 'codeapi';
  process.env.CODEAPI_JWT_ALLOWED_ALGS = 'EdDSA';
  process.env.CODEAPI_JWT_CLOCK_SKEW_SECONDS = '30';
  process.env.CODEAPI_JWT_MAX_TTL_SECONDS = '300';
  process.env.CODEAPI_JWT_KEY_CACHE_TTL_SECONDS = '0';
  process.env.CODEAPI_JWT_JWKS_JSON = jwksJson;
  delete process.env.CODEAPI_JWT_PUBLIC_KEYS_DIR;
  delete process.env.CODEAPI_JWT_PUBLIC_KEY;
  delete process.env.CODEAPI_JWT_HS256_SECRET;
}

export class FakeRedis {
  readonly entries = new Map<string, StoreEntry>();
  readonly writes: Array<{ op: string; key: string; value?: string; ttl?: number }> = [];

  async get(key: string): Promise<string | null> {
    return this.entries.get(key)?.value ?? null;
  }

  async set(key: string, value: string, ...args: (string | number)[]): Promise<'OK'> {
    const exIndex = args.findIndex(arg => String(arg).toUpperCase() === 'EX');
    const ttl = exIndex >= 0 ? Number(args[exIndex + 1]) : undefined;
    this.entries.set(key, { value, ttl });
    this.writes.push({ op: 'set', key, value, ttl });
    return 'OK';
  }

  async exists(...keys: string[]): Promise<number> {
    return keys.filter(key => this.entries.has(key)).length;
  }

  async del(...keys: string[]): Promise<number> {
    let removed = 0;
    for (const key of keys) {
      this.writes.push({ op: 'del', key });
      if (this.entries.delete(key)) removed++;
    }
    return removed;
  }

  async ping(): Promise<string> {
    return 'PONG';
  }

  /** replay-state registers Lua helpers at import; the harness never runs them. */
  defineCommand(): void {}

  /** Enough of the rate-limit-redis protocol for an always-allowing limiter. */
  async call(command: string, ...args: (string | number | Buffer)[]): Promise<unknown> {
    switch (command.toUpperCase()) {
      case 'SCRIPT':
        return createHash('sha1').update(String(args[1])).digest('hex');
      case 'EVALSHA':
        return args.length === 3 ? [false, -2] : [1, Number(args[4] ?? 60_000)];
      case 'DECR':
      case 'DEL':
        return 0;
      default:
        throw new Error(`Unsupported Redis command in harness: ${command}`);
    }
  }
}

export type ExecResultFactory = (jobData: Record<string, unknown>) => Record<string, unknown>;

export interface RouteHarness {
  baseUrl: string;
  redis: FakeRedis;
  jobs: Array<Record<string, unknown>>;
  logs: CapturedLog[];
  puts: CapturedPut[];
  fileServerCalls: CapturedFileServerCall[];
  objects: Map<string, { bytes: Buffer; headers: Record<string, string> }>;
  setDeleteHandler(handler: DeleteHandler | undefined): void;
  close(): Promise<void>;
}

function headerRecord(req: IncomingMessage): Record<string, string> {
  const out: Record<string, string> = {};
  for (const [name, value] of Object.entries(req.headers)) {
    if (value === undefined) continue;
    out[name] = Array.isArray(value) ? value.join(',') : value;
  }
  return out;
}

async function listen(server: Server): Promise<number> {
  const { promise, resolve } = Promise.withResolvers<number>();
  server.listen(0, '127.0.0.1', () => resolve((server.address() as AddressInfo).port));
  return promise;
}

async function closeServer(server: Server): Promise<void> {
  const { promise, resolve } = Promise.withResolvers<void>();
  server.close(() => resolve());
  server.closeAllConnections();
  return promise;
}

export async function installRouteHarness(options: {
  /** Absolute path of `service/src/queue.ts` in the tree under test. */
  queueModulePath: string;
  /** Absolute path of `service/src` in the tree under test. */
  srcDir: string;
  jwksJson: string;
}): Promise<RouteHarness> {
  const redis = new FakeRedis();
  const jobs: Array<Record<string, unknown>> = [];
  const makeQueue = (name: string) => ({
    name,
    async add(_jobName: string, data: Record<string, unknown>, opts?: { jobId?: string }) {
      jobs.push(data);
      const payload = data.payload as { session_id?: string } | undefined;
      return {
        id: opts?.jobId ?? `job-${jobs.length}`,
        async remove() {},
        async waitUntilFinished() {
          return { session_id: payload?.session_id ?? '', files: [], stdout: 'ok\n', stderr: '' };
        },
      };
    },
  });
  mock.module(options.queueModulePath, () => ({
    connection: redis,
    pyQueue: makeQueue('python'),
    otherQueue: makeQueue('other'),
    pyQueueEvents: {},
    otherQueueEvents: {},
    queueNames: { python: 'python', other: 'other' },
  }));

  configureJwtEnv(options.jwksJson);
  process.env.CODEAPI_INTERNAL_SERVICE_TOKEN = INTERNAL_TOKEN;

  /* Stub file server: records every forwarded call, keeps the bytes and sets
   * the `upload:` marker the real file server writes. */
  const puts: CapturedPut[] = [];
  const fileServerCalls: CapturedFileServerCall[] = [];
  const objects = new Map<string, { bytes: Buffer; headers: Record<string, string> }>();
  let deleteHandler: DeleteHandler | undefined;
  const fileServer = createServer(async (req, res) => {
    const url = req.url ?? '';
    const headers = headerRecord(req);
    fileServerCalls.push({ method: req.method ?? '', url, headers });
    const send = (status: number, body: unknown): void => {
      res.writeHead(status, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify(body));
    };
    const match = url.match(/^\/sessions\/([^/?]+)\/objects(?:\/([^/?]+))?(\/metadata)?/);
    if (!match) return send(404, { error: 'not found' });
    const [, sessionId, fileId, metadata] = match;
    const key = `${sessionId}/${fileId ?? ''}`;
    if (req.method === 'PUT' && fileId) {
      const chunks: Buffer[] = [];
      for await (const chunk of req) chunks.push(chunk as Buffer);
      const bytes = Buffer.concat(chunks);
      puts.push({ url, headers, bytes: bytes.length });
      objects.set(key, { bytes, headers });
      const sessionKey = await redis.get(`session:${sessionId}`);
      await redis.set(`upload:${sessionKey}${sessionId}${fileId}`, 'true', 'EX', 86400);
      return send(200, { filename: decodeURIComponent(headers['x-original-filename'] ?? ''), fileId, size: bytes.length });
    }
    const object = fileId ? objects.get(key) : undefined;
    if (req.method === 'GET' && fileId) {
      if (!object) return send(404, { error: 'File not found' });
      if (metadata) return send(200, { name: key, size: object.bytes.length });
      res.writeHead(200, { 'Content-Type': 'application/octet-stream', 'Content-Length': String(object.bytes.length) });
      return res.end(object.bytes);
    }
    if (req.method === 'GET') {
      return send(200, [...objects.keys()].filter(name => name.startsWith(`${sessionId}/`)));
    }
    if (req.method === 'DELETE' && fileId) {
      if (deleteHandler) {
        const outcome = deleteHandler(req, key);
        return send(outcome.status, outcome.body);
      }
      if (!objects.delete(key)) return send(404, { error: 'File not found' });
      return send(200, { message: 'File deleted successfully', session_id: sessionId, fileId });
    }
    return send(405, { error: 'unsupported' });
  });
  const fileServerPort = await listen(fileServer);

  const { env } = await import(`${options.srcDir}/config`);
  env.FILE_SERVER_URL = `http://127.0.0.1:${fileServerPort}`;
  env.LOCAL_MODE = false;
  env.MAX_UPLOAD_CHECKS = 1;
  env.MAX_UPLOAD_WAIT = 1;
  env.EGRESS_GRANT_SECRET = EGRESS_SECRET;
  env.EGRESS_GATEWAY_URL = 'http://egress-gateway.invalid';
  env.RUNTIME_SESSION_MODE = 'affinity';

  const logger = (await import(`${options.srcDir}/logger`)).default;
  const logs: CapturedLog[] = [];
  for (const level of ['error', 'warn', 'info', 'debug'] as const) {
    spyOn(logger, level).mockImplementation(((message: unknown, meta?: unknown) => {
      logs.push({ level, message: String(message), ...(meta === undefined ? {} : { meta }) });
      return logger;
    }) as never);
  }

  const { apiKeyAuth } = await import(`${options.srcDir}/middleware/auth`);
  const serviceRouter = (await import(`${options.srcDir}/service/router`)).default;
  (await import(`${options.srcDir}/lifecycle`)).setStartupComplete();

  const app = express();
  app.use(express.json({ limit: '10mb' }));
  const v1 = express.Router();
  v1.use(apiKeyAuth);
  v1.use(serviceRouter);
  app.use('/v1', v1);
  const apiServer = createServer(app);
  const apiPort = await listen(apiServer);

  return {
    baseUrl: `http://127.0.0.1:${apiPort}`,
    redis,
    jobs,
    logs,
    puts,
    fileServerCalls,
    objects,
    setDeleteHandler(handler) {
      deleteHandler = handler;
    },
    async close() {
      await Promise.all([closeServer(apiServer), closeServer(fileServer)]);
    },
  };
}

/** Replaces every nanoid-shaped token with a stable placeholder, in order of
 *  first appearance, so snapshots compare across runs and source trees.
 *  Tokens are collected where they stand alone and then replaced everywhere,
 *  including inside concatenations such as `upload:<key><sid><fid>`. */
export function normalizeIds(value: unknown): unknown {
  const json = JSON.stringify(value, (_key, inner) => (inner instanceof Error ? { error: inner.message } : inner));
  const tokens = new Map<string, string>();
  for (const [token] of json.matchAll(/(?<![A-Za-z0-9_-])[A-Za-z0-9_-]{21}(?![A-Za-z0-9_-])/g)) {
    if (!tokens.has(token)) tokens.set(token, `<id${tokens.size + 1}>`);
  }
  let replaced = json;
  for (const [token, placeholder] of tokens) replaced = replaced.split(token).join(placeholder);
  return JSON.parse(replaced);
}

export async function uploadForm(
  baseUrl: string,
  token: string,
  fields: Record<string, string>,
  files: Array<{ name: string; content: string }>,
  path = '/v1/upload',
  extraHeaders: Record<string, string> = {},
): Promise<{ status: number; body: unknown }> {
  const form = new FormData();
  for (const [name, value] of Object.entries(fields)) form.append(name, value);
  for (const file of files) form.append('file', new Blob([file.content], { type: 'text/plain' }), file.name);
  const response = await fetch(`${baseUrl}${path}`, {
    method: 'POST',
    headers: { Authorization: `Bearer ${token}`, ...extraHeaders },
    body: form,
  });
  return { status: response.status, body: await response.json().catch(() => null) };
}

export async function call(
  baseUrl: string,
  token: string,
  method: string,
  path: string,
  body?: unknown,
): Promise<{ status: number; body: unknown }> {
  const response = await fetch(`${baseUrl}${path}`, {
    method,
    headers: {
      Authorization: `Bearer ${token}`,
      ...(body === undefined ? {} : { 'Content-Type': 'application/json' }),
    },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  const text = await response.text();
  try {
    return { status: response.status, body: JSON.parse(text) };
  } catch {
    return { status: response.status, body: text };
  }
}
