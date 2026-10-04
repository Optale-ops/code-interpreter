import type { Response } from 'express';
import type * as t from '../types';
import {
    applyExecutionIdentity,
    executionIdentityFromPrincipal,
} from '../execution-identity';
import type { ExternalFetchPolicySnapshot } from '../external-fetch-policy';
import type { AgentRunSubject, FileDeleteTarget } from '../agent-run';

export type UserPrincipal = {
  userId: string;
  tenantId: string;
  role?: string;
  orgId?: string;
  serviceId?: string;
  externalUserId?: string;
  principalSource: 'librechat_jwt' | 'openid_reuse' | 'none' | string;
  authContextHash?: string;
  credentialId?: string;
  planId?: string;
    networkPolicy?: ExternalFetchPolicySnapshot;
    networkPolicyDigest?: string;
  agentRun?: undefined;
};

/**
 * A company Agent executing one run. There is no user here: `userId` is
 * absent by type, so no consumer can read the Agent as a human.
 */
export type AgentRunPrincipal = {
  tenantId: string;
  role: 'AGENT';
  principalSource: 'agent_run';
  authContextHash: string;
  credentialId?: string;
    networkPolicy?: ExternalFetchPolicySnapshot;
    networkPolicyDigest?: string;
  agentRun: AgentRunSubject & {
    /** Present only on deletion-only tokens (C3). */
    fileDelete?: FileDeleteTarget;
  };
  userId?: undefined;
  planId?: undefined;
};

export type CodeApiPrincipal = UserPrincipal | AgentRunPrincipal;

export function isAgentRunPrincipal(principal: CodeApiPrincipal | undefined): principal is AgentRunPrincipal {
  return principal?.agentRun !== undefined;
}

export function applyPrincipal(
    req: t.AuthenticatedRequest,
    principal: CodeApiPrincipal,
): void {
  req.codeApiPrincipal = principal;
  applyExecutionIdentity(req, executionIdentityFromPrincipal(principal));
  if (principal.agentRun) {
    req.codeApiAuthContext = {
      tenantId: principal.tenantId,
      principalSource: principal.principalSource,
      authContextHash: principal.authContextHash,
      networkPolicy: principal.networkPolicy,
      networkPolicyDigest: principal.networkPolicyDigest,
      agentRun: { agentId: principal.agentRun.agentId, runId: principal.agentRun.runId },
    };
    return;
  }
  if (principal.planId) {
    req.planId = principal.planId;
  }
  req.codeApiAuthContext = {
    userId: principal.userId,
    tenantId: principal.tenantId,
    orgId: principal.orgId,
    serviceId: principal.serviceId,
    externalUserId: principal.externalUserId,
    principalSource: principal.principalSource,
    authContextHash: principal.authContextHash,
        networkPolicy: principal.networkPolicy,
        networkPolicyDigest: principal.networkPolicyDigest,
  };
}

export function getPrincipal(
    req: t.AuthenticatedRequest,
): CodeApiPrincipal | undefined {
  if (req.codeApiPrincipal) {
    return req.codeApiPrincipal;
  }
  const ctx = req.codeApiAuthContext;
  /* Rebuilding from the auth context is a personal-only legacy path; an
   * agent_run principal always arrives through applyPrincipal. */
  if (!ctx?.userId || ctx.agentRun) {
    return undefined;
  }
  return {
    userId: ctx.userId,
    tenantId: ctx.tenantId ?? 'legacy',
    orgId: ctx.orgId,
    serviceId: ctx.serviceId,
    externalUserId: ctx.externalUserId,
    principalSource: ctx.principalSource ?? 'librechat_jwt',
    authContextHash: ctx.authContextHash,
        networkPolicy: ctx.networkPolicy,
        networkPolicyDigest: ctx.networkPolicyDigest,
  };
}

/**
 * Accepts a verified agent_run principal only when every Agent field is
 * present (a missing field is a refusal, never a personal default), and a
 * personal principal only with a userId.
 */
export function getPrincipalOrReject(
  req: t.AuthenticatedRequest,
  res: Response,
): CodeApiPrincipal | undefined {
  const principal = getPrincipal(req);
  if (principal?.agentRun) {
    if (principal.tenantId && principal.agentRun.agentId && principal.agentRun.runId) {
      return principal;
    }
    res.status(401).json({ error: 'Agent run principal is incomplete' });
    return undefined;
  }
  if (!principal?.userId) {
    res.status(401).json({ error: 'User not found' });
    return undefined;
  }
  return principal;
}

export function getCredentialId(req: t.AuthenticatedRequest): string {
  return getPrincipal(req)?.credentialId ?? '';
}
