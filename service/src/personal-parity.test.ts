/**
 * C6 personal parity. One deterministic fixture (fixed Ed25519 key, fixed
 * clock, fixed jti/UUIDs) drives every personal identity consumer and the
 * personal HTTP routes, and the result is compared with a golden file that
 * was generated from the pre-change engine (e9ad47c7). Any change to personal
 * token verification, auth context, sessionKeys, output/rate-limit buckets,
 * runtime-session ids, manifest/grant claims, replay state, forwarded
 * file-server headers, Redis writes, job data or log lines fails here.
 *
 * Regenerate only on the pre-change tree: PERSONAL_PARITY_WRITE=1.
 */
import { afterAll, beforeAll, expect, test } from 'bun:test';
import { createHash } from 'crypto';
import { existsSync, readFileSync, writeFileSync } from 'fs';
import { join } from 'path';
import {
  call,
  installRouteHarness,
  jwksFor,
  normalizeIds,
  signTestJwt,
  testSigningKey,
  uploadForm,
  type RouteHarness,
} from './test-support/route-harness';

const GOLDEN_PATH = join(import.meta.dir, 'test-support', 'personal-parity.golden.json');
const FIXED_NOW_SECONDS = 1_790_000_000;
const USER_ID = '65f0c0ffee0000000000abcd';
const TENANT = 'tenant-parity';
const RUN_UUID = '0b7f3c2e-9d4a-4c1b-8e2f-5a6b7c8d9e0f';
const PUBLIC_AGENT_KEY = 'agent_AbCdEfGhIjK';
const SKILL_ID = '65f0c0ffee0000000000beef';

let harness: RouteHarness;

function personalClaims(nowSeconds: number, overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    iss: 'librechat',
    aud: 'codeapi',
    sub: USER_ID,
    iat: nowSeconds,
    nbf: nowSeconds,
    exp: nowSeconds + 300,
    jti: '7d1e4c52-3f6a-4b8e-9c0d-1e2f3a4b5c6d',
    tenant_id: TENANT,
    role: 'USER',
    principal_source: 'librechat_jwt',
    auth_context_hash: 'b1f1c0de'.repeat(8),
    ...overrides,
  };
}

const TOKEN_VARIANTS: Record<string, Record<string, unknown>> = {
  console_personal: {},
  with_plan_and_org: { plan_id: 'pro', org_id: 'org_1', service_id: 'svc_1', external_user_id: 'ext_1' },
  legacy_chc_alias: { chc_user_id: 'chc_legacy_1' },
  openid_reuse: { principal_source: 'openid_reuse' },
  aud_array: { aud: ['other', 'codeapi'] },
  control_agent_looking_sub_with_run_id: { sub: '65f0c0ffee0000000000f00d', role: 'AGENT', run_id: RUN_UUID },
};

beforeAll(async () => {
  harness = await installRouteHarness({
    queueModulePath: join(import.meta.dir, 'queue.ts'),
    srcDir: import.meta.dir,
    jwksJson: jwksFor([{ kid: 'parity-kid', key: testSigningKey() }]),
  });
  process.env.CODEAPI_TENANT_ISOLATION_STRICT = 'true';
});

afterAll(async () => {
  await harness?.close();
});

async function unitSnapshot(): Promise<Record<string, unknown>> {
  const { verifyLibreChatJwt } = await import('./auth/librechat-jwt');
  const { applyPrincipal } = await import('./auth/principal');
  const { getExecutionIdentity } = await import('./execution-identity');
  const { resolveSessionKey, resolveOutputBucketSessionKey, parseUploadSessionKeyInput } = await import('./session-key');
  const { keyGenerator } = await import('./middleware/limits');
  const { resolveRuntimeSessionIdForExecRequest } = await import('./runtime-session/id');
  const { buildExecutionManifestClaims } = await import('./execution-manifest-claims');
  const { egressGrantFromExecutionClaims } = await import('./egress-grant');
  const { buildReplayExecutionState } = await import('./service/programmatic-state');
  const { checkContinuationPreconditions } = await import('./service/replay-state');
  type Req = Parameters<typeof applyPrincipal>[0];

  const realNow = Date.now;
  Date.now = () => FIXED_NOW_SECONDS * 1000;
  try {
    const out: Record<string, unknown> = {};
    for (const [name, overrides] of Object.entries(TOKEN_VARIANTS)) {
      const token = signTestJwt(personalClaims(FIXED_NOW_SECONDS, overrides));
      const principal = verifyLibreChatJwt(token);
      if (principal.agentRun) throw new Error('personal fixture verified as agent_run');
      const req = { ip: '127.0.0.1', headers: {}, header: () => undefined } as unknown as Req;
      applyPrincipal(req, principal);
      const identity = getExecutionIdentity(req);
      if (identity.agentRun) throw new Error('personal fixture resolved an agent_run identity');
      const sessionKeys = {
        user: resolveSessionKey(req, parseUploadSessionKeyInput({ kind: 'user', id: undefined, version: undefined, authContextUserId: principal.userId })),
        agentRun: resolveSessionKey(req, { kind: 'agent', id: RUN_UUID }),
        agentPublic: resolveSessionKey(req, { kind: 'agent', id: PUBLIC_AGENT_KEY }),
        skill: resolveSessionKey(req, { kind: 'skill', id: SKILL_ID, version: 3 }),
        outputBucket: resolveOutputBucketSessionKey(req),
      };
      const payload = {
        lang: 'py',
        code: 'print(1)',
        session_id: 'sess_output_parity_00',
        files: [{ id: 'file_parity_000000001', storage_session_id: 'sess_input_parity_001', name: 'in.csv' }],
      };
      const manifest = buildExecutionManifestClaims({
        req,
        executionId: 'exec_parity_0000000001',
        userId: principal.userId,
        sessionKey: sessionKeys.outputBucket,
        outputSessionId: 'sess_output_parity_00',
        payload: payload as never,
        nowSeconds: FIXED_NOW_SECONDS,
      });
      const replayState = buildReplayExecutionState({
        executionId: 'exec_parity_0000000001',
        sessionId: 'sess_output_parity_00',
        sessionKey: sessionKeys.outputBucket,
        userId: principal.userId,
        apiKeyId: '',
        authContext: req.codeApiAuthContext,
        identity,
        code: 'print(1)',
        tools: [],
        isPyPlot: false,
        timeout: 1000,
        language: 'python',
        now: FIXED_NOW_SECONDS * 1000,
      });
      const delta = { serializedByCallId: new Map<string, string>(), newCallIds: [], bytesDelta: 0 };
      out[name] = {
        tokenSha256: createHash('sha256').update(token).digest('hex'),
        principal,
        authContext: req.codeApiAuthContext,
        executionIdentity: identity,
        planId: req.planId ?? null,
        sessionKeys,
        rateLimitKey: keyGenerator(req as never),
        runtimeSessionId: resolveRuntimeSessionIdForExecRequest({
          mode: 'affinity',
          storageNamespace: identity.storageNamespace,
          canonicalUserId: identity.canonicalUserId,
          runtimeSessionHint: 'conv-parity',
          isSynthetic: false,
        }),
        manifest,
        grant: egressGrantFromExecutionClaims(manifest, 'grant_parity_00000001'),
        replayState,
        continuationSameUser: checkContinuationPreconditions({
          state: replayState,
          results: [],
          userId: principal.userId,
          apiKeyId: '',
          tenantId: identity.storageNamespace,
          authContextHash: identity.authContextHash,
          delta,
        }),
        continuationOtherUser: checkContinuationPreconditions({
          state: replayState,
          results: [],
          userId: 'someone_else',
          apiKeyId: '',
          tenantId: identity.storageNamespace,
          authContextHash: identity.authContextHash,
          delta,
        }),
      };
    }
    return out;
  } finally {
    Date.now = realNow;
  }
}

async function routeSnapshot(): Promise<Record<string, unknown>> {
  const now = Math.floor(Date.now() / 1000);
  const token = signTestJwt(personalClaims(now));
  const otherUserToken = signTestJwt(personalClaims(now, { sub: '65f0c0ffee0000000000dddd' }));
  const steps: Array<Record<string, unknown>> = [];
  const record = (name: string, result: { status: number; body: unknown }): void => {
    steps.push({ name, ...result });
  };

  const userUpload = await uploadForm(harness.baseUrl, token, { kind: 'user' }, [{ name: 'notes.txt', content: 'hello' }]);
  record('upload user', userUpload);
  const agentUpload = await uploadForm(
    harness.baseUrl,
    token,
    { kind: 'agent', id: RUN_UUID },
    [{ name: 'a.txt', content: 'aa' }, { name: 'dir/b.txt', content: 'bbb' }],
    '/v1/upload/batch',
  );
  record('upload/batch agent', agentUpload);
  const skillUpload = await uploadForm(
    harness.baseUrl,
    token,
    { kind: 'skill', id: SKILL_ID, version: '3', read_only: 'true' },
    [{ name: 'SKILL.md', content: '# skill' }],
    '/v1/upload/batch',
  );
  record('upload/batch skill', skillUpload);

  const userSession = (userUpload.body as { storage_session_id: string }).storage_session_id;
  const userFile = (userUpload.body as { files: Array<{ fileId: string }> }).files[0].fileId;
  const agentSession = (agentUpload.body as { storage_session_id: string }).storage_session_id;
  const agentFile = (agentUpload.body as { files: Array<{ fileId: string }> }).files[0].fileId;

  record('metadata user', await call(harness.baseUrl, token, 'GET', `/v1/sessions/${userSession}/objects/${userFile}?kind=user`));
  record('download agent', await call(harness.baseUrl, token, 'GET', `/v1/download/${agentSession}/${agentFile}?kind=agent&id=${RUN_UUID}`));
  record('files list user', await call(harness.baseUrl, token, 'GET', `/v1/files/${userSession}?kind=user`));
  record('download wrong kind', await call(harness.baseUrl, token, 'GET', `/v1/download/${userSession}/${userFile}?kind=agent&id=${RUN_UUID}`));
  record('download other user', await call(harness.baseUrl, otherUserToken, 'GET', `/v1/download/${userSession}/${userFile}?kind=user`));
  record('exec', await call(harness.baseUrl, token, 'POST', '/v1/exec', {
    lang: 'py',
    code: 'print(1)',
    runtime_session_hint: 'conv-parity',
    files: [
      { id: userFile, storage_session_id: userSession, name: 'notes.txt', kind: 'user', resource_id: USER_ID },
      { id: agentFile, storage_session_id: agentSession, name: 'a.txt', kind: 'agent', resource_id: RUN_UUID },
    ],
  }));
  record('exec foreign file', await call(harness.baseUrl, otherUserToken, 'POST', '/v1/exec', {
    lang: 'py',
    code: 'print(1)',
    files: [{ id: userFile, storage_session_id: userSession, name: 'notes.txt', kind: 'user', resource_id: USER_ID }],
  }));
  record('delete user', await call(harness.baseUrl, token, 'DELETE', `/v1/files/${userSession}/${userFile}?kind=user`));

  const jobs = harness.jobs.map(job => {
    const { egressGrantClaims, ...rest } = job as { egressGrantClaims?: Record<string, unknown> };
    /* iat/exp follow the wall clock in this live part; every other claim byte is compared. */
    const { iat: _iat, exp: _exp, ...claims } = egressGrantClaims ?? {};
    return { ...rest, egressGrantClaims: claims };
  });
  const puts = harness.puts.map(put => {
    const { 'x-codeapi-internal-token': internal, host: _host, ...headers } = put.headers;
    return { url: put.url, bytes: put.bytes, internalTokenPresent: Boolean(internal), headers };
  });
  return {
    steps,
    redisWrites: harness.redis.writes,
    puts,
    jobs,
    logs: harness.logs,
  };
}

test('personal identity consumers, routes and log lines are byte-identical to the pre-change engine', async () => {
  const snapshot = normalizeIds({ unit: await unitSnapshot(), routes: await routeSnapshot() }) as {
    routes: { jobs: Array<{ egressGrantClaims: { input_files?: unknown[]; read_sessions?: unknown[] } }> };
  };
  /* The engine sorts these by raw (random) storage ids; once ids are
   * placeholders the order is noise, the membership is the contract. */
  for (const job of snapshot.routes.jobs) {
    job.egressGrantClaims.input_files?.sort((a, b) => JSON.stringify(a).localeCompare(JSON.stringify(b)));
    job.egressGrantClaims.read_sessions?.sort((a, b) => JSON.stringify(a).localeCompare(JSON.stringify(b)));
  }
  if (process.env.PERSONAL_PARITY_WRITE === '1') {
    writeFileSync(GOLDEN_PATH, `${JSON.stringify(snapshot, null, 2)}\n`);
  }
  expect(existsSync(GOLDEN_PATH)).toBe(true);
  const golden = JSON.parse(readFileSync(GOLDEN_PATH, 'utf8'));
  expect(snapshot).toEqual(golden);
  /* toEqual ignores key order; serialized log lines, claims and state do not. */
  expect(JSON.stringify(snapshot)).toBe(JSON.stringify(golden));
});
