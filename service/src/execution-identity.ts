import type { CodeApiPrincipal, UserPrincipal } from './auth/principal';
import type { AgentRunSubject } from './agent-run';
import type { AuthenticatedRequest, CodeApiAuthContext } from './types';

const DEFAULT_SINGLE_TENANT_NAMESPACE = 'legacy';
const DEFAULT_PRINCIPAL_SOURCE = 'librechat_jwt';

interface ExecutionIdentityShared {
  /** Core storage/rate-limit namespace. Enterprise adapters map this from tenant identity. */
  storageNamespace: string;
  /** Back-compat alias for wire/persisted fields that still use tenant naming. */
  tenantId: string;
  orgId?: string;
  serviceId?: string;
  externalUserId?: string;
  principalSource: string;
  authContextHash?: string;
  credentialId?: string;
  planId?: string;
}

export interface UserExecutionIdentity extends ExecutionIdentityShared {
  /** Requesting user from the authenticated principal. */
  userId: string;
  /** User identity to persist across replay and sandbox capability scopes. */
  canonicalUserId: string;
  agentRun?: undefined;
}

/** A verified agent_run subject. It has no user: every consumer branches on `agentRun`. */
export interface AgentRunExecutionIdentity extends ExecutionIdentityShared {
  agentRun: AgentRunSubject;
  userId?: undefined;
  canonicalUserId?: undefined;
}

export type ExecutionIdentity = UserExecutionIdentity | AgentRunExecutionIdentity;

export interface BuildExecutionIdentityArgs {
  userId: string;
  authContext?: CodeApiAuthContext;
  principal?: UserPrincipal;
  canonicalUserId?: string;
  storageNamespace?: string;
  orgId?: string;
  serviceId?: string;
  externalUserId?: string;
  principalSource?: string;
  authContextHash?: string;
  credentialId?: string;
  planId?: string;
}

export interface ResolveStorageNamespaceOptions {
  requireTenant?: boolean;
  onMissingTenant?: () => Error;
  singleTenantNamespace?: string;
}

export function resolveSingleTenantNamespace(): string {
  const configured = process.env.CODEAPI_JWT_SINGLE_TENANT_ID;
  if (configured != null && configured.trim() !== '') {
    return configured.trim();
  }
  return DEFAULT_SINGLE_TENANT_NAMESPACE;
}

export function resolveStorageNamespace(
  authContext: CodeApiAuthContext | undefined,
  options: ResolveStorageNamespaceOptions = {},
): string {
  const tenant = authContext?.tenantId;
  if (tenant) {
    return tenant;
  }
  if (options.requireTenant === true) {
    throw options.onMissingTenant?.() ?? new Error('tenantId missing from auth context');
  }
  return options.singleTenantNamespace ?? resolveSingleTenantNamespace();
}

/** Personal execution identity. agent_run identities come only from
 *  `agentRunExecutionIdentity`, never from a user id argument. */
export function buildExecutionIdentity(args: BuildExecutionIdentityArgs): UserExecutionIdentity {
  const principal = args.principal;
  const authContext = args.authContext;
  const storageNamespace = args.storageNamespace
    ?? principal?.tenantId
    ?? resolveStorageNamespace(authContext);
  const canonicalUserId = args.canonicalUserId
    ?? authContext?.userId
    ?? principal?.userId
    ?? args.userId;

  return {
    userId: args.userId,
    canonicalUserId,
    storageNamespace,
    tenantId: storageNamespace,
    orgId: args.orgId ?? principal?.orgId ?? authContext?.orgId,
    serviceId: args.serviceId ?? principal?.serviceId ?? authContext?.serviceId,
    externalUserId: args.externalUserId ?? principal?.externalUserId ?? authContext?.externalUserId,
    principalSource: args.principalSource
      ?? principal?.principalSource
      ?? authContext?.principalSource
      ?? DEFAULT_PRINCIPAL_SOURCE,
    authContextHash: args.authContextHash ?? principal?.authContextHash ?? authContext?.authContextHash,
    credentialId: args.credentialId ?? principal?.credentialId,
    planId: args.planId ?? principal?.planId,
  };
}

export function agentRunExecutionIdentity(args: {
  tenantId: string;
  agentRun: AgentRunSubject;
  principalSource: string;
  authContextHash?: string;
  credentialId?: string;
}): AgentRunExecutionIdentity {
  return {
    storageNamespace: args.tenantId,
    tenantId: args.tenantId,
    principalSource: args.principalSource,
    authContextHash: args.authContextHash,
    credentialId: args.credentialId,
    agentRun: { agentId: args.agentRun.agentId, runId: args.agentRun.runId },
  };
}

export function executionIdentityFromPrincipal(principal: CodeApiPrincipal): ExecutionIdentity {
  if (principal.agentRun) {
    return agentRunExecutionIdentity({
      tenantId: principal.tenantId,
      agentRun: principal.agentRun,
      principalSource: principal.principalSource,
      authContextHash: principal.authContextHash,
      credentialId: principal.credentialId,
    });
  }
  return buildExecutionIdentity({
    userId: principal.userId,
    canonicalUserId: principal.userId,
    storageNamespace: principal.tenantId,
    principal,
  });
}

export function getExecutionIdentity(
  req: AuthenticatedRequest,
  fallbackUserId = req.codeApiAuthContext?.userId ?? req.codeApiPrincipal?.userId ?? '',
): ExecutionIdentity {
  if (req.executionIdentity) {
    return req.executionIdentity;
  }
  const principal = req.codeApiPrincipal;
  if (principal?.agentRun) {
    return executionIdentityFromPrincipal(principal);
  }
  const authContext = req.codeApiAuthContext;
  if (authContext?.agentRun) {
    /* No user fallback for an Agent: a context without its tenant is refused. */
    if (!authContext.tenantId) {
      throw new Error('agent_run auth context has no tenant');
    }
    return agentRunExecutionIdentity({
      tenantId: authContext.tenantId,
      agentRun: authContext.agentRun,
      principalSource: authContext.principalSource ?? '',
      authContextHash: authContext.authContextHash,
    });
  }
  return buildExecutionIdentity({
    userId: fallbackUserId,
    authContext,
    principal,
  });
}

export function applyExecutionIdentity(
  req: AuthenticatedRequest,
  identity: ExecutionIdentity,
): void {
  req.executionIdentity = identity;
}
