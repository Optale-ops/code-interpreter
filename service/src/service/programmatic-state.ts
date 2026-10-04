import type * as t from '../types';
import type { LCTool } from '../preamble';
import type { ExecutionState } from './replay-state';
import { buildExecutionIdentity, type ExecutionIdentity } from '../execution-identity';

export interface BuildReplayExecutionStateParams {
  executionId: string;
  sessionId: string;
  sessionKey: string;
  /** Personal subject; unused for an agent_run identity. */
  userId?: string;
  apiKeyId: string;
  authContext?: t.CodeApiAuthContext;
  identity?: ExecutionIdentity;
  code: string;
  tools: LCTool[];
  files?: t.RequestFile[];
  isPyPlot: boolean;
  timeout: number;
  language: 'python' | 'bash';
  now?: number;
}

export function buildReplayExecutionState(
  params: BuildReplayExecutionStateParams,
): ExecutionState {
  const now = params.now ?? Date.now();
  const replay = {
    apiKeyId: params.apiKeyId,
    startTime: now,
    lastActivity: now,
    mode: 'replay' as const,
    userCode: params.code,
    tools: params.tools,
    files: params.files,
    isPyPlot: params.isPyPlot,
    timeout: params.timeout,
    callCount: 0,
    language: params.language,
  };
  /* agent_run state persists the Agent subject and its private sessionKey;
   * it never gains a userId. */
  if (params.identity?.agentRun) {
    return {
      execution_id: params.executionId,
      session_id: params.sessionId,
      sessionKey: params.sessionKey,
      agentRun: params.identity.agentRun,
      tenantId: params.identity.storageNamespace,
      principalSource: params.identity.principalSource,
      authContextHash: params.identity.authContextHash,
      ...replay,
    };
  }
  if (params.userId === undefined) {
    throw new Error('replay execution state requires a user or an agent_run subject');
  }
  const identity = params.identity ?? buildExecutionIdentity({
    userId: params.userId,
    authContext: params.authContext,
  });
  return {
    execution_id: params.executionId,
    session_id: params.sessionId,
    sessionKey: params.sessionKey,
    userId: params.userId,
    tenantId: identity.storageNamespace,
    canonicalUserId: identity.canonicalUserId,
    orgId: identity.orgId,
    serviceId: identity.serviceId,
    externalUserId: identity.externalUserId,
    principalSource: identity.principalSource,
    authContextHash: identity.authContextHash,
    ...replay,
  };
}
