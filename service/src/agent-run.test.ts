/**
 * agent_run subject (contract v2, Security conditions C1-C5): claim grammar,
 * the private run namespace, upload kinds, the deletion-only token, the
 * durable owner binding, and every identity consumer. Route cases run the
 * real apiKeyAuth + service router through the in-process harness.
 */
import { afterAll, beforeAll, beforeEach, describe, expect, test } from 'bun:test';
import { randomUUID } from 'crypto';
import { join } from 'path';
import {
  call,
  installRouteHarness,
  jwksFor,
  signTestJwt,
  testSigningKey,
  uploadForm,
  type CapturedLog,
  type RouteHarness,
} from './test-support/route-harness';
import { CodeApiJwtAuthError, verifyLibreChatJwt } from './auth/librechat-jwt';
import { applyPrincipal } from './auth/principal';
import {
  OWNER_BINDING_HEADER,
  agentRunSessionKey,
  ownerBindingFromHeader,
  ownerBindingValue,
  signOwnerBinding,
} from './agent-run';
import { keyGenerator } from './middleware/limits';
import { deriveRuntimeSessionId } from './runtime-session/id';
import { buildExecutionManifestClaims } from './execution-manifest-claims';
import { openEgressGrant, prepareSandboxEgress, sealEgressGrant } from './egress-grant';
import { continuationSubjectMatches, replaySessionKey, type ExecutionState } from './service/replay-state';
import { buildReplayExecutionState } from './service/programmatic-state';
import { getExecutionIdentity } from './execution-identity';
import type * as t from './types';
import { env } from './config';

const TENANT = 'tenant-a';
const OTHER_TENANT = 'tenant-b';
const AGENT = '65f0c0ffee0000000000a9e1';
const OTHER_AGENT = '65f0c0ffee0000000000a9e2';
const RUN1 = '0b7f3c2e-9d4a-4c1b-8e2f-5a6b7c8d9e01';
const RUN2 = '0b7f3c2e-9d4a-4c1b-8e2f-5a6b7c8d9e02';
const USER = '65f0c0ffee0000000000abcd';
const CONTEXT_HASH = 'c0ffee11'.repeat(8);
const BOUND_KID = 'bound-kid';
const SKILL_ID = '65f0c0ffee0000000000beef';

let harness: RouteHarness;
let savedHardened = false;
const bindings = new Map<string, string>();

function nowSeconds(): number {
  return Math.floor(Date.now() / 1000);
}

function agentClaims(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  const now = nowSeconds();
  return {
    iss: 'librechat',
    aud: 'codeapi',
    sub: AGENT,
    iat: now,
    nbf: now,
    exp: now + 300,
    jti: randomUUID(),
    tenant_id: TENANT,
    role: 'AGENT',
    principal_source: 'agent_run',
    run_id: RUN1,
    auth_context_hash: CONTEXT_HASH,
    ...overrides,
  };
}

function userClaims(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  const now = nowSeconds();
  return {
    iss: 'librechat',
    aud: 'codeapi',
    sub: USER,
    iat: now,
    nbf: now,
    exp: now + 300,
    jti: randomUUID(),
    tenant_id: TENANT,
    role: 'USER',
    principal_source: 'librechat_jwt',
    auth_context_hash: 'b1f1c0de'.repeat(8),
    ...overrides,
  };
}

const agentToken = (overrides: Record<string, unknown> = {}): string => signTestJwt(agentClaims(overrides));
const userToken = (overrides: Record<string, unknown> = {}): string => signTestJwt(userClaims(overrides));

function jwtReason(token: string): string {
  try {
    verifyLibreChatJwt(token);
    return 'accepted';
  } catch (error) {
    if (error instanceof CodeApiJwtAuthError) return `${error.reason}: ${error.message}`;
    throw error;
  }
}

/** Every log line emitted while `fn` runs must be free of raw Agent identity. */
async function withoutRawIdentityInLogs<T>(fn: () => Promise<T>): Promise<T> {
  const start = harness.logs.length;
  const result = await fn();
  const emitted: CapturedLog[] = harness.logs.slice(start);
  const serialized = JSON.stringify(emitted);
  for (const raw of [AGENT, RUN1, RUN2, CONTEXT_HASH, `${TENANT}:`]) {
    expect(serialized).not.toContain(raw);
  }
  return result;
}

type UploadBody = { storage_session_id: string; files: Array<{ fileId: string }> };

async function agentUpload(
  fields: Record<string, string>,
  token = agentToken(),
  path = '/v1/upload',
  extraHeaders: Record<string, string> = {},
): Promise<{ status: number; body: unknown }> {
  return uploadForm(harness.baseUrl, token, fields, [{ name: 'in.txt', content: 'agent input' }], path, extraHeaders);
}

function uploadedRef(result: { body: unknown }): { sid: string; fid: string } {
  const body = result.body as UploadBody;
  return { sid: body.storage_session_id, fid: body.files[0].fileId };
}

beforeAll(async () => {
  harness = await installRouteHarness({
    queueModulePath: join(import.meta.dir, 'queue.ts'),
    srcDir: import.meta.dir,
    jwksJson: jwksFor([
      { kid: 'parity-kid', key: testSigningKey() },
      { kid: BOUND_KID, key: testSigningKey(Buffer.alloc(32, 9)), tenants: [TENANT] },
    ]),
  });
  /* The stub file server applies the real file server's owner-binding rules
   * through the same exported helper: only a signed binding for this exact
   * object is stored; owner-bound deletion requires an exact match. */
  savedHardened = env.HARDENED_SANDBOX_MODE;
  env.HARDENED_SANDBOX_MODE = true;
  harness.setPutHandler((headers, sid, fid) => {
    const owner = ownerBindingFromHeader(headers[OWNER_BINDING_HEADER.toLowerCase()], sid, fid);
    if (!owner.ok) return { status: 400, body: { error: owner.error } };
    if (owner.binding) bindings.set(`${sid}/${fid}`, owner.binding);
    return undefined;
  });
  harness.setDeleteHandler((req, key) => {
    if (!harness.objects.has(key)) return { status: 404, body: { error: 'File not found' } };
    const expected = req.headers['x-codeapi-owner-expect'];
    if (expected !== undefined) {
      const stored = bindings.get(key);
      if (!stored || stored !== expected) return { status: 403, body: { error: 'Owner binding does not match' } };
    }
    harness.objects.delete(key);
    bindings.delete(key);
    return { status: 200, body: { message: 'File deleted successfully' } };
  });
});

afterAll(async () => {
  env.HARDENED_SANDBOX_MODE = savedHardened;
  await harness?.close();
});

beforeEach(() => {
  delete process.env.CODEAPI_TENANT_ISOLATION_STRICT;
});

describe('agent_run claim grammar', () => {
  test('a well-formed agent_run token verifies to an Agent principal with no user', () => {
    const principal = verifyLibreChatJwt(agentToken());
    expect(principal).toEqual({
      tenantId: TENANT,
      role: 'AGENT',
      principalSource: 'agent_run',
      authContextHash: CONTEXT_HASH,
      agentRun: { agentId: AGENT, runId: RUN1 },
    });
    expect('userId' in principal).toBe(false);
  });

  test('tenant_id is required for agent_run whether strict isolation is on or off', () => {
    for (const strict of [undefined, 'true', 'false']) {
      if (strict === undefined) delete process.env.CODEAPI_TENANT_ISOLATION_STRICT;
      else process.env.CODEAPI_TENANT_ISOLATION_STRICT = strict;
      expect(jwtReason(agentToken({ tenant_id: undefined }))).toBe('malformed_claims: tenant_id is required for agent_run');
      expect(jwtReason(agentToken({ tenant_id: '' }))).toBe('malformed_claims: tenant_id is required for agent_run');
    }
  });

  test('malformed agent_run values are refused, never normalized', () => {
    const cases: Array<[Record<string, unknown>, string]> = [
      [{ sub: 'agent_AbCdEfGhIjK' }, 'sub must be a canonical Agent id'],
      [{ sub: AGENT.toUpperCase() }, 'sub must be a canonical Agent id'],
      [{ sub: `${AGENT}0` }, 'sub must be a canonical Agent id'],
      [{ run_id: undefined }, 'run_id must be a canonical UUID'],
      [{ run_id: RUN1.toUpperCase() }, 'run_id must be a canonical UUID'],
      [{ run_id: RUN1.replace(/-/g, '') }, 'run_id must be a canonical UUID'],
      [{ run_id: `${RUN1}:x` }, 'run_id must be a canonical UUID'],
      [{ tenant_id: 'tenant:a' }, 'tenant_id is not canonical'],
      [{ tenant_id: ' tenant-a' }, 'tenant_id is not canonical'],
      [{ role: 'USER' }, 'role must be AGENT'],
      [{ role: undefined }, 'role must be AGENT'],
      [{ org_id: 'org_1' }, 'org_id is not accepted for agent_run'],
      [{ service_id: 'svc_1' }, 'service_id is not accepted for agent_run'],
      [{ external_user_id: 'ext_1' }, 'external_user_id is not accepted for agent_run'],
      [{ chc_user_id: 'chc_1' }, 'chc_user_id is not accepted for agent_run'], // leak-check:allow
      [{ plan_id: 'pro' }, 'plan_id is not accepted for agent_run'],
      [{ auth_context_hash: undefined }, 'auth_context_hash is required'],
      [{ file_delete: { storage_session_id: 'a'.repeat(21) } }, 'file_delete must hold exactly'],
      [{ file_delete: { storage_session_id: 'a'.repeat(21), file_id: 'b'.repeat(21), kind: 'agent' } }, 'file_delete must hold exactly'],
      [{ file_delete: { storage_session_id: 'short', file_id: 'b'.repeat(21) } }, 'file_delete target is not a storage object id'],
      [{ file_delete: 'x' }, 'file_delete must hold exactly'],
    ];
    for (const [overrides, message] of cases) {
      expect(jwtReason(agentToken(overrides))).toContain(message);
    }
  });

  test('#18: a key bound to tenants signs agent_run only for those tenants', () => {
    const boundKey = testSigningKey(Buffer.alloc(32, 9));
    expect(jwtReason(signTestJwt(agentClaims(), boundKey, BOUND_KID))).toBe('accepted');
    expect(jwtReason(signTestJwt(agentClaims({ tenant_id: OTHER_TENANT }), boundKey, BOUND_KID))).toBe(
      'tenant_not_allowed: JWT tenant is not allowed for this key',
    );
  });

  test('a personal token carrying file_delete is refused, not ignored', () => {
    expect(jwtReason(userToken({ file_delete: { storage_session_id: 'a'.repeat(21), file_id: 'b'.repeat(21) } }))).toBe(
      'malformed_claims: file_delete is only accepted for agent_run',
    );
  });

  test('a personal token with an Agent-looking sub stays a personal principal', () => {
    const principal = verifyLibreChatJwt(userToken({ sub: AGENT, role: 'AGENT', run_id: RUN1 }));
    expect(principal.agentRun).toBeUndefined();
    expect(principal.userId).toBe(AGENT);
  });
});

describe('agent_run identity consumers (C5)', () => {
  function agentReq(runId = RUN1, agentId = AGENT): t.AuthenticatedRequest {
    const req = { ip: '127.0.0.1', headers: {}, header: () => undefined } as unknown as t.AuthenticatedRequest;
    applyPrincipal(req, verifyLibreChatJwt(agentToken({ run_id: runId, sub: agentId })));
    return req;
  }

  test('auth context and execution identity carry the Agent subject and no user id', () => {
    const req = agentReq();
    expect(req.codeApiAuthContext).toEqual({
      tenantId: TENANT,
      principalSource: 'agent_run',
      authContextHash: CONTEXT_HASH,
      networkPolicy: undefined,
      networkPolicyDigest: undefined,
      agentRun: { agentId: AGENT, runId: RUN1 },
    });
    const identity = getExecutionIdentity(req);
    expect(identity.agentRun).toEqual({ agentId: AGENT, runId: RUN1 });
    expect(identity.userId).toBeUndefined();
    expect(identity.canonicalUserId).toBeUndefined();
    expect(req.planId).toBeUndefined();
  });

  test('rate-limit bucket is stable per Agent across runs and separate from a user with the same id', () => {
    const first = keyGenerator(agentReq(RUN1) as never);
    expect(first).toBe(`${TENANT}:agent:${AGENT}`);
    expect(keyGenerator(agentReq(RUN2) as never)).toBe(first);
    expect(keyGenerator(agentReq(RUN1, OTHER_AGENT) as never)).not.toBe(first);
    const userReq = { ip: '127.0.0.1', headers: {}, header: () => undefined } as unknown as t.AuthenticatedRequest;
    applyPrincipal(userReq, verifyLibreChatJwt(userToken({ sub: AGENT })));
    expect(keyGenerator(userReq as never)).toBe(`${TENANT}:user:${AGENT}`);
  });

  test('runtime session scope separates runs, Agents and users whatever the hint', () => {
    const run1 = deriveRuntimeSessionId({ storageNamespace: TENANT, agentRun: { agentId: AGENT, runId: RUN1 }, hint: 'conv' });
    expect(run1).toMatch(/^rt_[0-9a-f]{40}$/);
    expect(deriveRuntimeSessionId({ storageNamespace: TENANT, agentRun: { agentId: AGENT, runId: RUN1 }, hint: 'conv' })).toBe(run1);
    expect(deriveRuntimeSessionId({ storageNamespace: TENANT, agentRun: { agentId: AGENT, runId: RUN2 }, hint: 'conv' })).not.toBe(run1);
    expect(deriveRuntimeSessionId({ storageNamespace: TENANT, agentRun: { agentId: OTHER_AGENT, runId: RUN1 }, hint: 'conv' })).not.toBe(run1);
    expect(deriveRuntimeSessionId({ storageNamespace: OTHER_TENANT, agentRun: { agentId: AGENT, runId: RUN1 }, hint: 'conv' })).not.toBe(run1);
    expect(deriveRuntimeSessionId({ storageNamespace: TENANT, canonicalUserId: AGENT, hint: 'conv' })).not.toBe(run1);
    expect(deriveRuntimeSessionId({ storageNamespace: TENANT, canonicalUserId: `${AGENT}\u0000${RUN1}`, hint: 'conv' })).not.toBe(run1);
  });

  test('manifest and grant carry principal_source, agent_id and run_id and no user_id', () => {
    const req = agentReq();
    const claims = buildExecutionManifestClaims({
      req,
      executionId: 'exec_agent_000000001',
      agentRun: { agentId: AGENT, runId: RUN1 },
      sessionKey: agentRunSessionKey(TENANT, { agentId: AGENT, runId: RUN1 }),
      outputSessionId: 'sess_output_agent_001',
      payload: { files: [], session_id: 'sess_output_agent_001' } as unknown as t.PayloadBody,
      nowSeconds: 1_790_000_000,
    });
    expect(claims).toMatchObject({ tenant_id: TENANT, agent_id: AGENT, run_id: RUN1, principal_source: 'agent_run' });
    expect('user_id' in claims).toBe(false);
    const grant = openEgressGrant(
      sealEgressGrant({ ...claims, grant_id: 'grant_agent_00000001', iat: nowSeconds(), exp: nowSeconds() + 60 }, 'x'.repeat(32)),
      'x'.repeat(32),
    );
    expect(grant).toMatchObject({ agent_id: AGENT, run_id: RUN1, principal_source: 'agent_run' });
    expect(grant.user_id).toBeUndefined();
    const masked = prepareSandboxEgress({
      payload: { files: [], session_id: 'sess_output_agent_001' } as unknown as t.PayloadBody,
      claims,
      grantId: 'grant_agent_00000001',
      secret: 'x'.repeat(32),
    }).executionManifestClaims;
    expect(masked.agent_id).toMatch(/^agent:/);
    expect(masked.run_id).toMatch(/^run:/);
    expect(masked.user_id).toBeUndefined();
  });

  test('a grant naming both a user and an Agent, or an Agent without its run, is refused', () => {
    const base = {
      grant_id: 'grant_agent_00000001',
      exec_id: 'exec_1',
      tenant_id: TENANT,
      session_key: 'k',
      input_files: [],
      read_sessions: [],
      output_session_id: 'out',
      max_upload_bytes: 1,
      max_output_files: 1,
      max_requests: 1,
      iat: nowSeconds(),
      exp: nowSeconds() + 60,
      principal_source: 'agent_run',
    };
    const secret = 'x'.repeat(32);
    expect(() => openEgressGrant(sealEgressGrant({ ...base, agent_id: AGENT, run_id: RUN1, user_id: USER }, secret), secret)).toThrow();
    expect(() => openEgressGrant(sealEgressGrant({ ...base, agent_id: AGENT }, secret), secret)).toThrow();
    expect(() => openEgressGrant(sealEgressGrant({ ...base, user_id: USER }, secret), secret)).toThrow();
  });

  test('continuation equality compares kind, Agent, run, tenant and context hash, never a sub string', () => {
    const req = agentReq();
    const state = buildReplayExecutionState({
      executionId: 'exec_1',
      sessionId: 'sess_1',
      sessionKey: agentRunSessionKey(TENANT, { agentId: AGENT, runId: RUN1 }),
      apiKeyId: '',
      identity: getExecutionIdentity(req),
      code: 'x',
      tools: [],
      isPyPlot: false,
      timeout: 1000,
      language: 'python',
    });
    expect(state.userId).toBeUndefined();
    const same = { agentRun: { agentId: AGENT, runId: RUN1 }, tenantId: TENANT, authContextHash: CONTEXT_HASH };
    expect(continuationSubjectMatches(state, same)).toBe(true);
    expect(continuationSubjectMatches(state, { ...same, agentRun: { agentId: AGENT, runId: RUN2 } })).toBe(false);
    expect(continuationSubjectMatches(state, { ...same, agentRun: { agentId: OTHER_AGENT, runId: RUN1 } })).toBe(false);
    expect(continuationSubjectMatches(state, { ...same, tenantId: OTHER_TENANT })).toBe(false);
    expect(continuationSubjectMatches(state, { ...same, authContextHash: 'other' })).toBe(false);
    /* A user whose id equals the Agent id, or a user with no id, never matches Agent state. */
    expect(continuationSubjectMatches(state, { userId: AGENT, tenantId: TENANT, authContextHash: CONTEXT_HASH })).toBe(false);
    expect(continuationSubjectMatches(state, { tenantId: TENANT })).toBe(false);
    /* And an Agent never matches personal state. */
    const personal = { ...state, agentRun: undefined, userId: AGENT, principalSource: 'librechat_jwt' } as ExecutionState;
    expect(continuationSubjectMatches(personal, same)).toBe(false);
  });

  test('replay output key: agent_run state requires its persisted private key, no userId fallback', () => {
    const agentState = { execution_id: 'e', session_id: 's', agentRun: { agentId: AGENT, runId: RUN1 }, userId: AGENT } as ExecutionState;
    expect(() => replaySessionKey(agentState)).toThrow('no session key');
    expect(replaySessionKey({ ...agentState, sessionKey: 'k' })).toBe('k');
    expect(replaySessionKey({ execution_id: 'e', session_id: 's', userId: 'legacy-key' } as ExecutionState)).toBe('legacy-key');
  });
});

describe('owner binding (C4)', () => {
  test('only a binding signed for this exact object is accepted', () => {
    const binding = ownerBindingValue(TENANT, { agentId: AGENT, runId: RUN1 });
    const sid = 'a'.repeat(21);
    const fid = 'b'.repeat(21);
    const signed = signOwnerBinding(sid, fid, binding);
    expect(ownerBindingFromHeader(signed, sid, fid)).toEqual({ ok: true, binding });
    expect(ownerBindingFromHeader(undefined, sid, fid)).toEqual({ ok: true });
    expect(ownerBindingFromHeader(signed, sid, 'c'.repeat(21)).ok).toBe(false);
    expect(ownerBindingFromHeader(`${ownerBindingValue(TENANT, { agentId: AGENT, runId: RUN2 })}.${'A'.repeat(43)}`, sid, fid).ok).toBe(false);
    expect(ownerBindingFromHeader(binding, sid, fid).ok).toBe(false);
    expect(ownerBindingFromHeader([signed ?? ''], sid, fid).ok).toBe(false);
  });
});

describe('agent_run routes', () => {
  test('C1: upload kind=agent id=<signed run> lands in the private run key with a server-written owner binding', async () => {
    const result = await withoutRawIdentityInLogs(() => agentUpload({ kind: 'agent', id: RUN1 }));
    expect(result.status).toBe(200);
    const { sid, fid } = uploadedRef(result);
    expect(await harness.redis.get(`session:${sid}`)).toBe(`${TENANT}:agent-run:${AGENT}:${RUN1}`);
    expect(bindings.get(`${sid}/${fid}`)).toBe(ownerBindingValue(TENANT, { agentId: AGENT, runId: RUN1 }));
  });

  test('C1: upload kind=agent with an id other than the signed run is refused', async () => {
    expect((await agentUpload({ kind: 'agent', id: RUN2 })).status).toBe(403);
    expect((await agentUpload({ kind: 'agent', id: AGENT })).status).toBe(403);
    expect((await agentUpload({ kind: 'agent', id: RUN2 }, agentToken(), '/v1/upload/batch')).status).toBe(403);
  });

  test('C1: upload kind=user is refused for agent_run', async () => {
    const putsBefore = harness.puts.length;
    expect((await agentUpload({ kind: 'user' })).status).toBe(403);
    expect((await agentUpload({ kind: 'user' }, agentToken(), '/v1/upload/batch')).status).toBe(403);
    expect((await agentUpload({ kind: 'user', id: AGENT })).status).toBe(403);
    expect((await agentUpload({ kind: 'user', id: AGENT }, agentToken(), '/v1/upload/batch')).status).toBe(403);
    expect(harness.puts.length).toBe(putsBefore);
  });

  test('C1: upload kind=skill needs read_only=true and stays in the shared skill key without a binding', async () => {
    expect((await agentUpload({ kind: 'skill', id: SKILL_ID, version: '2' })).status).toBe(403);
    expect((await agentUpload({ kind: 'skill', id: SKILL_ID, version: '2', read_only: 'false' }, agentToken(), '/v1/upload/batch')).status).toBe(403);
    const ok = await agentUpload({ kind: 'skill', id: SKILL_ID, version: '2', read_only: 'true' }, agentToken(), '/v1/upload/batch');
    expect(ok.status).toBe(200);
    const { sid, fid } = uploadedRef(ok);
    expect(await harness.redis.get(`session:${sid}`)).toBe(`${TENANT}:skill:${SKILL_ID}:v:2`);
    expect(bindings.has(`${sid}/${fid}`)).toBe(false);
    /* Shared skill inputs are readable; an Agent cannot delete them. */
    const read = await call(harness.baseUrl, agentToken(), 'GET', `/v1/download/${sid}/${fid}?kind=skill&id=${SKILL_ID}&version=2`);
    expect(read.status).toBe(200);
    const del = await call(harness.baseUrl, agentToken(), 'DELETE', `/v1/files/${sid}/${fid}?kind=skill&id=${SKILL_ID}&version=2`);
    expect(del.status).toBe(403);
  });

  test('C4: a client-supplied owner header on upload is ignored; the binding comes from the verified principal', async () => {
    const forged = signOwnerBinding('x'.repeat(21), 'y'.repeat(21), ownerBindingValue(TENANT, { agentId: AGENT, runId: RUN2 }));
    const result = await agentUpload({ kind: 'agent', id: RUN1 }, agentToken(), '/v1/upload', {
      [OWNER_BINDING_HEADER]: forged ?? 'forged',
    });
    expect(result.status).toBe(200);
    const { sid, fid } = uploadedRef(result);
    expect(bindings.get(`${sid}/${fid}`)).toBe(ownerBindingValue(TENANT, { agentId: AGENT, runId: RUN1 }));
  });

  test('the Agent reads its own run objects', async () => {
    const { sid, fid } = uploadedRef(await agentUpload({ kind: 'agent', id: RUN1 }));
    await withoutRawIdentityInLogs(async () => {
      expect((await call(harness.baseUrl, agentToken(), 'GET', `/v1/download/${sid}/${fid}?kind=agent&id=${RUN1}`)).body).toBe('agent input');
      expect((await call(harness.baseUrl, agentToken(), 'GET', `/v1/sessions/${sid}/objects/${fid}?kind=agent&id=${RUN1}`)).status).toBe(200);
      expect((await call(harness.baseUrl, agentToken(), 'GET', `/v1/files/${sid}?kind=agent&id=${RUN1}`)).status).toBe(200);
    });
  });

  test('collision: a user token with kind=agent id=<agentId|runId|agent-run:A:R> cannot touch Agent objects', async () => {
    const { sid, fid } = uploadedRef(await agentUpload({ kind: 'agent', id: RUN1 }));
    for (const id of [AGENT, RUN1, `agent-run:${AGENT}:${RUN1}`]) {
      const query = `kind=agent&id=${encodeURIComponent(id)}`;
      for (const token of [userToken(), userToken({ sub: AGENT })]) {
        expect((await call(harness.baseUrl, token, 'GET', `/v1/download/${sid}/${fid}?${query}`)).status).toBe(403);
        expect((await call(harness.baseUrl, token, 'GET', `/v1/files/${sid}?${query}`)).status).toBe(403);
        expect((await call(harness.baseUrl, token, 'GET', `/v1/sessions/${sid}/objects/${fid}?${query}`)).status).toBe(403);
        expect((await call(harness.baseUrl, token, 'DELETE', `/v1/files/${sid}/${fid}?${query}`)).status).toBe(403);
        const exec = await call(harness.baseUrl, token, 'POST', '/v1/exec', {
          lang: 'py',
          code: 'print(1)',
          files: [{ id: fid, storage_session_id: sid, name: 'in.txt', kind: 'agent', resource_id: id }],
        });
        expect(exec.status).toBe(403);
      }
    }
    /* A user upload with kind=agent id=<run> stays in the shared agent key. */
    const userUpload = await uploadForm(harness.baseUrl, userToken(), { kind: 'agent', id: RUN1 }, [{ name: 'u.txt', content: 'u' }]);
    expect(await harness.redis.get(`session:${uploadedRef(userUpload).sid}`)).toBe(`${TENANT}:agent:${RUN1}`);
    /* And the Agent cannot read that shared key either. */
    const { sid: userSid, fid: userFid } = uploadedRef(userUpload);
    expect((await call(harness.baseUrl, agentToken(), 'GET', `/v1/download/${userSid}/${userFid}?kind=agent&id=${RUN1}`)).status).toBe(403);
  });

  test('the Agent cannot read a user bucket', async () => {
    const userUpload = await uploadForm(harness.baseUrl, userToken({ sub: AGENT }), { kind: 'user' }, [{ name: 'u.txt', content: 'u' }]);
    const { sid, fid } = uploadedRef(userUpload);
    expect((await call(harness.baseUrl, agentToken(), 'GET', `/v1/download/${sid}/${fid}?kind=user`)).status).toBe(400);
    expect((await call(harness.baseUrl, agentToken(), 'GET', `/v1/download/${sid}/${fid}?kind=user&id=${AGENT}`)).status).toBe(403);
    expect((await call(harness.baseUrl, agentToken(), 'GET', `/v1/files/${sid}?kind=user&id=${AGENT}`)).status).toBe(403);
  });

  test('cross-run replay: a token for run R2 cannot read, execute with or delete run R1 objects', async () => {
    const { sid, fid } = uploadedRef(await agentUpload({ kind: 'agent', id: RUN1 }));
    const run2 = agentToken({ run_id: RUN2 });
    expect((await call(harness.baseUrl, run2, 'GET', `/v1/download/${sid}/${fid}?kind=agent&id=${RUN1}`)).status).toBe(403);
    expect((await call(harness.baseUrl, run2, 'GET', `/v1/download/${sid}/${fid}?kind=agent&id=${RUN2}`)).status).toBe(403);
    expect((await call(harness.baseUrl, run2, 'DELETE', `/v1/files/${sid}/${fid}?kind=agent&id=${RUN2}`)).status).toBe(403);
    const exec = await call(harness.baseUrl, run2, 'POST', '/v1/exec', {
      lang: 'py',
      code: 'print(1)',
      files: [{ id: fid, storage_session_id: sid, name: 'in.txt', kind: 'agent', resource_id: RUN1 }],
    });
    expect(exec.status).toBe(403);
    /* Same Agent and run but another tenant's (bound) token. */
    const otherTenant = signTestJwt(agentClaims({ tenant_id: OTHER_TENANT }), testSigningKey(Buffer.alloc(32, 9)), BOUND_KID);
    expect((await call(harness.baseUrl, otherTenant, 'GET', `/v1/download/${sid}/${fid}?kind=agent&id=${RUN1}`)).status).toBe(401);
    const otherTenantUnbound = agentToken({ tenant_id: OTHER_TENANT });
    expect((await call(harness.baseUrl, otherTenantUnbound, 'GET', `/v1/download/${sid}/${fid}?kind=agent&id=${RUN1}`)).status).toBe(403);
  });

  test('exec: outputs go to the private key and every downstream identity is the Agent subject', async () => {
    const { sid, fid } = uploadedRef(await agentUpload({ kind: 'agent', id: RUN1 }));
    const jobsBefore = harness.jobs.length;
    const result = await withoutRawIdentityInLogs(() => call(harness.baseUrl, agentToken(), 'POST', '/v1/exec', {
      lang: 'py',
      code: 'print(1)',
      runtime_session_hint: 'conv-1',
      files: [{ id: fid, storage_session_id: sid, name: 'in.txt', kind: 'agent', resource_id: RUN1 }],
    }));
    expect(result.status).toBe(200);
    const job = harness.jobs[jobsBefore] as t.JobData & { egressGrantClaims: Record<string, unknown> };
    expect(job.userId).toBeUndefined();
    expect(job.canonicalUserId).toBeUndefined();
    expect(job.agentRun).toEqual({ agentId: AGENT, runId: RUN1 });
    expect(job.principalSource).toBe('agent_run');
    expect(job.runtimeSessionId).toBe(
      deriveRuntimeSessionId({ storageNamespace: TENANT, agentRun: { agentId: AGENT, runId: RUN1 }, hint: 'conv-1' }),
    );
    const privateKey = `${TENANT}:agent-run:${AGENT}:${RUN1}`;
    expect(job.egressGrantClaims).toMatchObject({
      tenant_id: TENANT,
      agent_id: AGENT,
      run_id: RUN1,
      principal_source: 'agent_run',
      session_key: privateKey,
    });
    expect('user_id' in job.egressGrantClaims).toBe(false);
    const outputSession = job.payload.session_id as string;
    expect(await harness.redis.get(`session:${outputSession}`)).toBe(privateKey);

    /* An output the gateway wrote (binding from the grant) is readable by the run, not by users. */
    const outputFid = 'o'.repeat(21);
    const put = await fetch(`${harness.fileServerUrl}/sessions/${outputSession}/objects/${outputFid}`, {
      method: 'PUT',
      headers: {
        'Content-Type': 'text/plain',
        'X-Original-Filename': 'out.txt',
        [OWNER_BINDING_HEADER]: signOwnerBinding(outputSession, outputFid, ownerBindingValue(TENANT, { agentId: AGENT, runId: RUN1 })) ?? '',
      },
      body: 'output',
    });
    expect(put.status).toBe(200);
    expect((await call(harness.baseUrl, agentToken(), 'GET', `/v1/download/${outputSession}/${outputFid}?kind=agent&id=${RUN1}`)).body).toBe('output');
    expect((await call(harness.baseUrl, userToken({ sub: AGENT }), 'GET', `/v1/download/${outputSession}/${outputFid}?kind=agent&id=${AGENT}`)).status).toBe(403);
    expect((await call(harness.baseUrl, userToken(), 'GET', `/v1/download/${outputSession}/${outputFid}?kind=user`)).status).toBe(403);
  });

  test('exec with a kind=user file reference is refused for agent_run', async () => {
    const exec = await call(harness.baseUrl, agentToken(), 'POST', '/v1/exec', {
      lang: 'py',
      code: 'print(1)',
      files: [{ id: 'f'.repeat(21), storage_session_id: 's'.repeat(21), name: 'x', kind: 'user', resource_id: AGENT }],
    });
    expect(exec.status).toBe(403);
  });
});

describe('deletion-only tokens (C3) and durable owner binding (C4)', () => {
  function deletionToken(sid: string, fid: string, overrides: Record<string, unknown> = {}): string {
    return agentToken({ file_delete: { storage_session_id: sid, file_id: fid }, ...overrides });
  }

  test('every route other than the signed DELETE target is refused before dispatch', async () => {
    const { sid, fid } = uploadedRef(await agentUpload({ kind: 'agent', id: RUN1 }));
    const other = uploadedRef(await agentUpload({ kind: 'agent', id: RUN1 }));
    const token = deletionToken(sid, fid);
    const jobsBefore = harness.jobs.length;
    const putsBefore = harness.puts.length;
    const refused: Array<[string, string, unknown?]> = [
      ['POST', '/v1/exec', { lang: 'py', code: 'print(1)' }],
      ['POST', '/v1/exec/programmatic', { code: 'x', tools: [{ name: 't' }] }],
      ['POST', '/v1/exec/programmatic', { continuation_token: 'x', tool_results: [{ call_id: 'call_001', result: 1 }] }],
      ['GET', `/v1/download/${sid}/${fid}?kind=agent&id=${RUN1}`],
      ['GET', `/v1/files/${sid}?kind=agent&id=${RUN1}`],
      ['GET', `/v1/sessions/${sid}/objects/${fid}?kind=agent&id=${RUN1}`],
      ['GET', `/v1/files/${sid}/${fid}?kind=agent&id=${RUN1}`],
      ['DELETE', `/v1/files/${other.sid}/${other.fid}?kind=agent&id=${RUN1}`],
      ['DELETE', `/v1/files/${sid}/${other.fid}?kind=agent&id=${RUN1}`],
      ['DELETE', `/v1/files/${sid}/${fid}?kind=agent&id=${RUN2}`],
      ['DELETE', `/v1/files/${sid}/${fid}?kind=user`],
      ['DELETE', `/v1/files/${sid}/${fid}?kind=skill&id=${SKILL_ID}&version=1`],
      ['DELETE', `/v1/files/${sid}/${fid}?kind=agent&id=${RUN1}&version=1`],
      ['DELETE', `/v1/files/${sid}/${fid}`],
      ['DELETE', `/v1/files/${sid}/${fid}/?kind=agent&id=${RUN1}`],
      ['DELETE', `/v1/sessions/${sid}/objects/${fid}?kind=agent&id=${RUN1}`],
    ];
    for (const [method, path, body] of refused) {
      const result = await call(harness.baseUrl, token, method, path, body);
      expect([method, path, result.status]).toEqual([method, path, 403]);
    }
    const uploadCases: Array<Record<string, string>> = [
      { kind: 'agent', id: RUN1 },
      { kind: 'skill', id: SKILL_ID, version: '1', read_only: 'true' },
    ];
    for (const fields of uploadCases) {
      expect((await agentUpload(fields, token)).status).toBe(403);
      expect((await agentUpload(fields, token, '/v1/upload/batch')).status).toBe(403);
    }
    expect(harness.jobs.length).toBe(jobsBefore);
    expect(harness.puts.length).toBe(putsBefore);
    expect(harness.objects.has(`${sid}/${fid}`)).toBe(true);
  });

  test('the signed target is deleted while the session cache is present', async () => {
    const { sid, fid } = uploadedRef(await agentUpload({ kind: 'agent', id: RUN1 }));
    const result = await withoutRawIdentityInLogs(() =>
      call(harness.baseUrl, deletionToken(sid, fid), 'DELETE', `/v1/files/${sid}/${fid}?kind=agent&id=${RUN1}`));
    expect(result.status).toBe(200);
    expect(harness.objects.has(`${sid}/${fid}`)).toBe(false);
  });

  test('after the 24 h session cache expires the binding authorizes deletion; repeat is not-found', async () => {
    const { sid, fid } = uploadedRef(await agentUpload({ kind: 'agent', id: RUN1 }));
    await harness.redis.del(`session:${sid}`);
    const path = `/v1/files/${sid}/${fid}?kind=agent&id=${RUN1}`;

    /* Without file_delete there is no deletion exception. */
    expect((await call(harness.baseUrl, agentToken(), 'DELETE', path)).status).toBe(403);
    /* Another run's or Agent's deletion token for the same target: binding mismatch. */
    expect((await call(harness.baseUrl, deletionToken(sid, fid, { run_id: RUN2 }), 'DELETE', `/v1/files/${sid}/${fid}?kind=agent&id=${RUN2}`)).status).toBe(403);
    expect((await call(harness.baseUrl, deletionToken(sid, fid, { sub: OTHER_AGENT }), 'DELETE', path)).status).toBe(403);
    expect((await call(harness.baseUrl, deletionToken(sid, fid, { tenant_id: OTHER_TENANT }), 'DELETE', path)).status).toBe(403);
    expect(harness.objects.has(`${sid}/${fid}`)).toBe(true);

    const deleted = await withoutRawIdentityInLogs(() => call(harness.baseUrl, deletionToken(sid, fid), 'DELETE', path));
    expect(deleted.status).toBe(200);
    expect(harness.objects.has(`${sid}/${fid}`)).toBe(false);
    expect(bindings.has(`${sid}/${fid}`)).toBe(false);
    const expectHeaders = harness.fileServerCalls.filter(c => c.method === 'DELETE' && c.url.endsWith(`/${sid}/objects/${fid}`)).map(c => c.headers['x-codeapi-owner-expect']);
    expect(expectHeaders.at(-1)).toBe(ownerBindingValue(TENANT, { agentId: AGENT, runId: RUN1 }));

    expect((await call(harness.baseUrl, deletionToken(sid, fid), 'DELETE', path)).status).toBe(404);
  });

  test('an object with no binding is never reported deleted through the binding path', async () => {
    const sid = uploadedRef(await agentUpload({ kind: 'agent', id: RUN1 })).sid;
    const fid = 'u'.repeat(21);
    await fetch(`${harness.fileServerUrl}/sessions/${sid}/objects/${fid}`, {
      method: 'PUT',
      headers: { 'Content-Type': 'text/plain', 'X-Original-Filename': 'unbound.txt' },
      body: 'unbound',
    });
    await harness.redis.del(`session:${sid}`);
    expect((await call(harness.baseUrl, deletionToken(sid, fid), 'DELETE', `/v1/files/${sid}/${fid}?kind=agent&id=${RUN1}`)).status).toBe(403);
    expect(harness.objects.has(`${sid}/${fid}`)).toBe(true);
  });

  test('C4: a PUT with a forged owner header for another run cannot change the binding; that run cannot delete', async () => {
    const { sid, fid } = uploadedRef(await agentUpload({ kind: 'agent', id: RUN1 }));
    const run2Binding = ownerBindingValue(TENANT, { agentId: AGENT, runId: RUN2 });
    for (const forged of [`${run2Binding}.${'A'.repeat(43)}`, signOwnerBinding('z'.repeat(21), fid, run2Binding) ?? '', run2Binding]) {
      const put = await fetch(`${harness.fileServerUrl}/sessions/${sid}/objects/${fid}`, {
        method: 'PUT',
        headers: { 'Content-Type': 'text/plain', 'X-Original-Filename': 'in.txt', [OWNER_BINDING_HEADER]: forged },
        body: 'overwrite',
      });
      expect(put.status).toBe(400);
    }
    expect(bindings.get(`${sid}/${fid}`)).toBe(ownerBindingValue(TENANT, { agentId: AGENT, runId: RUN1 }));
    await harness.redis.del(`session:${sid}`);
    expect((await call(harness.baseUrl, deletionToken(sid, fid, { run_id: RUN2 }), 'DELETE', `/v1/files/${sid}/${fid}?kind=agent&id=${RUN2}`)).status).toBe(403);
    expect(harness.objects.get(`${sid}/${fid}`)?.bytes.toString()).toBe('agent input');
  });

  test('refused agent_run tokens leave no raw identity in logs', async () => {
    await withoutRawIdentityInLogs(async () => {
      expect((await call(harness.baseUrl, agentToken({ run_id: 'not-a-uuid' }), 'GET', `/v1/files/${'s'.repeat(21)}?kind=agent&id=${RUN1}`)).status).toBe(401);
      expect((await call(harness.baseUrl, deletionToken('s'.repeat(21), 'f'.repeat(21)), 'GET', `/v1/files/${'s'.repeat(21)}?kind=agent&id=${RUN1}`)).status).toBe(403);
    });
  });
});

describe('agent_run availability (hardened sandbox + internal service auth)', () => {
  test('agent_run is refused with 401 unless hardened mode and internal service auth are both on; personal is unaffected', async () => {
    const path = `/v1/files/${'s'.repeat(21)}?kind=agent&id=${RUN1}`;
    const savedToken = process.env.CODEAPI_INTERNAL_SERVICE_TOKEN;
    try {
      env.HARDENED_SANDBOX_MODE = false;
      expect((await call(harness.baseUrl, agentToken(), 'GET', path)).status).toBe(401);
      expect((await call(harness.baseUrl, userToken(), 'GET', `/v1/files/${'s'.repeat(21)}?kind=user`)).status).toBe(403);
      env.HARDENED_SANDBOX_MODE = true;
      delete process.env.CODEAPI_INTERNAL_SERVICE_TOKEN;
      expect((await call(harness.baseUrl, agentToken(), 'GET', path)).status).toBe(401);
      expect((await call(harness.baseUrl, userToken(), 'GET', `/v1/files/${'s'.repeat(21)}?kind=user`)).status).toBe(403);
      process.env.CODEAPI_INTERNAL_SERVICE_TOKEN = savedToken;
      /* Both on: the token is accepted (403 here is the session-key refusal past auth). */
      expect((await call(harness.baseUrl, agentToken(), 'GET', path)).status).toBe(403);
      expect(harness.logs.some(l => l.message.includes('agent_run_unavailable'))).toBe(true);
    } finally {
      env.HARDENED_SANDBOX_MODE = true;
      process.env.CODEAPI_INTERNAL_SERVICE_TOKEN = savedToken;
    }
  });
});
