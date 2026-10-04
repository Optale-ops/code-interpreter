/**
 * Agent-run subject: a company Agent executing code for one run.
 *
 * The verified JWT (`principal_source: 'agent_run'`) is the only source of
 * this identity. Its private storage key is derived here from the verified
 * principal and never from a caller-selectable kind/id, so no `kind=agent`
 * upload by a user token can produce it: after the namespace, `agent:` and
 * `agent-run:` differ at the sixth character.
 */
import { createHash, createHmac, timingSafeEqual } from 'crypto';
import { INTERNAL_SERVICE_TOKEN_ENV } from './internal-service-auth';

export const AGENT_RUN_PRINCIPAL_SOURCE = 'agent_run';

/** Canonical lowercase Mongo ObjectId of the Agent (never the public Agent key). */
export const AGENT_ID_PATTERN = /^[0-9a-f]{24}$/;
/** Canonical lowercase UUID: the producing run's responseMessageId. */
export const RUN_ID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;

export interface AgentRunSubject {
  agentId: string;
  runId: string;
}

/** The one storage object a deletion-only token may remove. */
export interface FileDeleteTarget {
  storageSessionId: string;
  fileId: string;
}

export function agentRunSessionKey(storageNamespace: string, subject: AgentRunSubject): string {
  return `${storageNamespace}:agent-run:${subject.agentId}:${subject.runId}`;
}

export function hashIdentityLabel(value: string): string {
  return createHash('sha256').update(value).digest('hex').slice(0, 12);
}

/** Log fields for an agent_run subject: kind plus hashed tenant/Agent/run, never raw ids. */
export function agentRunLogFields(tenantId: string | undefined, subject: AgentRunSubject): Record<string, string | undefined> {
  return {
    subjectKind: AGENT_RUN_PRINCIPAL_SOURCE,
    tenantHash: tenantId ? hashIdentityLabel(tenantId) : undefined,
    agentHash: hashIdentityLabel(subject.agentId),
    runHash: hashIdentityLabel(subject.runId),
  };
}

/** Private agent-run session keys embed raw Agent/run ids; log a hash instead.
 *  Personal keys are returned unchanged. */
export function sessionKeyForLog<T extends string | null | undefined>(sessionKey: T): T | string {
  if (typeof sessionKey === 'string' && /^[^:]+:agent-run:/.test(sessionKey)) {
    return `agent-run#${hashIdentityLabel(sessionKey)}`;
  }
  return sessionKey;
}

// ---------------------------------------------------------------------------
// Durable owner binding for agent-run objects (C4)
// ---------------------------------------------------------------------------

/** Internal api/gateway → file_server header carrying a signed binding. */
export const OWNER_BINDING_HEADER = 'X-CodeAPI-Owner-Binding';
/** Internal api → file_server header: delete only if the stored binding equals this. */
export const OWNER_EXPECT_HEADER = 'X-CodeAPI-Owner-Expect';
/** MinIO user-metadata name; stored with the object, so it lives exactly as long as the bytes. */
export const OWNER_METADATA = 'X-Amz-Meta-Codeapi-Owner';
/** How MinIO returns `OWNER_METADATA` from statObject. */
export const OWNER_METADATA_STAT_KEY = 'codeapi-owner';

/**
 * Opaque binding of an object to (tenant, Agent, run). Stored as a hash, so
 * object metadata listings never carry raw identity ids.
 */
export function ownerBindingValue(tenantId: string, subject: AgentRunSubject): string {
  const digest = createHash('sha256')
    .update(JSON.stringify([AGENT_RUN_PRINCIPAL_SOURCE, tenantId, subject.agentId, subject.runId]))
    .digest('hex');
  return `agent_run.${digest}`;
}

function ownerBindingKey(): Buffer | undefined {
  const token = (process.env[INTERNAL_SERVICE_TOKEN_ENV] ?? '').trim();
  if (!token) return undefined;
  return createHmac('sha256', token).update('codeapi-owner-binding:v1').digest();
}

function ownerBindingMac(key: Buffer, sessionId: string, fileId: string, binding: string): string {
  return createHmac('sha256', key).update(`${sessionId}/${fileId}\n${binding}`).digest('base64url');
}

/**
 * Header value the api (at upload) and the gateway (for sandbox outputs) send
 * so the file server stores the binding for exactly this object. Undefined
 * when internal service auth is not configured: the file server then cannot
 * tell an internal caller from anyone else, so no binding is written.
 */
export function signOwnerBinding(sessionId: string, fileId: string, binding: string): string | undefined {
  const key = ownerBindingKey();
  if (!key) return undefined;
  return `${binding}.${ownerBindingMac(key, sessionId, fileId, binding)}`;
}

export type OwnerBindingHeaderResult =
  | { ok: true; binding?: string }
  | { ok: false; error: string };

/**
 * File-server side. Only a binding signed by an internal caller for this exact
 * session/object is stored; anything else in the header is a forgery and the
 * PUT is refused, so a forged header can neither set nor change a binding.
 */
export function ownerBindingFromHeader(
  header: string | string[] | undefined,
  sessionId: string,
  fileId: string,
): OwnerBindingHeaderResult {
  if (header === undefined) return { ok: true };
  const value = Array.isArray(header) ? undefined : header;
  const key = ownerBindingKey();
  const match = value?.match(/^(agent_run\.[0-9a-f]{64})\.([A-Za-z0-9_-]{43})$/);
  if (!key || !match) return { ok: false, error: 'Owner binding is not accepted' };
  const expected = Buffer.from(ownerBindingMac(key, sessionId, fileId, match[1]));
  const actual = Buffer.from(match[2]);
  if (expected.length !== actual.length || !timingSafeEqual(expected, actual)) {
    return { ok: false, error: 'Owner binding is not accepted' };
  }
  return { ok: true, binding: match[1] };
}
