import type { Response, NextFunction } from 'express';
import type { AuthenticatedRequest } from '../types';
import { connection } from '../queue';
import { isValidId } from '../utils';
import { env } from '../config';
import { resolveSessionKey, parseUploadSessionKeyInput, SessionKeyResolutionError } from '../session-key';
import { LibreChatJwtAuthProvider, CodeApiJwtAuthError } from '../auth/librechat-jwt';
import { applyPrincipal, type AgentRunPrincipal, type CodeApiPrincipal } from '../auth/principal';
import { applyLocalPrincipal } from '../auth/local';
import { agentRunLogFields, ownerBindingValue, sessionKeyForLog } from '../agent-run';
import { internalServiceAuthEnabled } from '../internal-service-auth';
import { AuthProviderConfigError, getAuthProviderMode } from '../auth/provider';
import {
  authenticateSyntheticRequest,
  CODEAPI_SYNTHETIC_AUTH_HEADER,
  hasSyntheticAccessToken,
} from '../auth/synthetic';
import logger from '../logger';

/**
 * Mirrors the helper in `service/router.ts`. Returns true when the
 * error was a SessionKeyResolutionError and the response was sent
 * (with a logged trail); false otherwise so the caller can rethrow.
 * Centralizing the log gives a server-side breadcrumb for sessionKey
 * misconfigurations that would otherwise only surface in response
 * bodies.
 */
const logSessionKeyResolutionError = (
  err: unknown,
  res: Response,
  req: AuthenticatedRequest,
  context: string,
): boolean => {
  if (err instanceof SessionKeyResolutionError) {
    const agentRun = req.codeApiAuthContext?.agentRun;
    logger.error(`sessionKey resolution failed (${context})`, {
      status: err.status,
      message: err.message,
      method: req.method,
      path: req.path,
      ...(agentRun
        ? agentRunLogFields(req.codeApiAuthContext?.tenantId, agentRun)
        : {
          requestUserId: req.codeApiAuthContext?.userId,
          authContextUserId: req.codeApiAuthContext?.userId,
          tenantId: req.codeApiAuthContext?.tenantId,
        }),
    });
    res.status(err.status).json({ error: err.message });
    return true;
  }
  return false;
};

const jwtProvider = new LibreChatJwtAuthProvider();

/**
 * True when an unverified bearer token declares agent_run. Used only to drop
 * the query string (which carries the run id) from refusal logs; it grants
 * nothing.
 */
function bearerDeclaresAgentRun(req: AuthenticatedRequest): boolean {
  const payload = req.header('Authorization')?.match(/^Bearer\s+[^.\s]+\.([^.\s]+)\./i)?.[1];
  if (!payload) return false;
  try {
    return (JSON.parse(Buffer.from(payload, 'base64url').toString('utf8')) as { principal_source?: unknown })
      .principal_source === 'agent_run';
  } catch {
    return false;
  }
}

function authLogMeta(req: AuthenticatedRequest, extra: Record<string, unknown> = {}): Record<string, unknown> {
  const agentRun = req.codeApiAuthContext?.agentRun;
  const redactQuery = agentRun !== undefined || (!req.codeApiPrincipal && bearerDeclaresAgentRun(req));
  const path = req.originalUrl || req.path;
  return {
    method: req.method,
    path: redactQuery ? path.split('?')[0] : path,
    ip: req.ip,
    authProvider: process.env.CODEAPI_AUTH_PROVIDER || 'librechat-jwt',
    hasBearerToken: Boolean(req.header('Authorization')?.match(/^Bearer\s+(.+)$/i)?.[1]?.trim()),
    hasApiKeyHeader: Boolean(req.header('X-API-Key')),
    hasSyntheticToken: hasSyntheticAccessToken(req),
    principalSource: req.codeApiPrincipal?.principalSource,
    /* agent_run: subject kind and hashed ids only; no raw ids or context hash. */
    ...(agentRun
      ? agentRunLogFields(req.codeApiAuthContext?.tenantId, agentRun)
      : {
        userId: req.codeApiAuthContext?.userId,
        tenantId: req.codeApiAuthContext?.tenantId,
        authContextHash: req.codeApiAuthContext?.authContextHash,
      }),
    ...extra,
  };
}

/**
 * C3: a deletion-only token is honoured for exactly one request shape,
 * `DELETE /files/<sid>/<fid>?kind=agent&id=<run>` with the signed target, and
 * refused for every other method, route and query before any handler runs.
 */
function fileDeleteRequestMatches(req: AuthenticatedRequest, principal: AgentRunPrincipal): boolean {
  const target = principal.agentRun.fileDelete;
  if (!target) return false;
  const queryKeys = Object.keys(req.query).sort().join(',');
  return (
    req.method === 'DELETE' &&
    req.path === `/files/${target.storageSessionId}/${target.fileId}` &&
    queryKeys === 'id,kind' &&
    req.query.kind === 'agent' &&
    req.query.id === principal.agentRun.runId
  );
}

export const apiKeyAuth = async (
  req: AuthenticatedRequest,
  res: Response,
  next: NextFunction
): Promise<void | Response> => {
  if (env.LOCAL_MODE === true) {
    applyLocalPrincipal(req);
    logger.debug('CodeAPI local request authenticated', authLogMeta(req, { mode: 'local' }));
    next();
    return;
  }

  const legacyApiKeyHeader = req.header('X-API-Key') ?? '';
  const bearerToken = req.header('Authorization')?.match(/^Bearer\s+(.+)$/i)?.[1]?.trim();
  const syntheticToken = req.header(CODEAPI_SYNTHETIC_AUTH_HEADER)?.trim();
  const authHeaderCount = [legacyApiKeyHeader, bearerToken, syntheticToken].filter(Boolean).length;
  if (authHeaderCount > 1) {
    logger.warn('Rejecting ambiguous CodeAPI auth headers', authLogMeta(req));
    return res.status(400).json({ error: 'Ambiguous authentication headers' });
  }

  try {
    const syntheticAuthResult = authenticateSyntheticRequest(req);
    if (syntheticAuthResult !== null) {
      if (!syntheticAuthResult.ok) {
        const logMeta = authLogMeta(req, { mode: 'synthetic', reason: syntheticAuthResult.reason });
        if (syntheticAuthResult.status >= 500) {
          logger.error('Rejecting synthetic CodeAPI request', logMeta);
        } else {
          logger.warn('Rejecting synthetic CodeAPI request', logMeta);
        }
        return res.status(syntheticAuthResult.status).json({ error: syntheticAuthResult.error });
      }

      applyPrincipal(req, syntheticAuthResult.principal);
      logger.debug('CodeAPI synthetic request authenticated', authLogMeta(req, { mode: 'synthetic' }));
      next();
      return;
    }

    const mode = getAuthProviderMode();
    let principal: CodeApiPrincipal | null = null;

    if (legacyApiKeyHeader) {
      logger.warn('Rejecting legacy CodeAPI API key header', authLogMeta(req, { mode }));
      return res.status(401).json({ error: 'Bearer token is required' });
    }

    if (mode === 'none') {
      if (process.env.CODEAPI_ALLOW_AUTH_PROVIDER_NONE !== 'true') {
        logger.error(
          'Rejecting CODEAPI_AUTH_PROVIDER=none outside local mode',
          authLogMeta(req, { mode }),
        );
        return res
          .status(500)
          .json({ error: 'CodeAPI auth provider none is only allowed in local mode' });
      }
      const userId =
        req.header('User-Id') || (req.body as { user_id?: string })?.user_id || 'anonymous';
      principal = {
        userId,
        tenantId: 'local',
        principalSource: 'none',
      };
    } else {
      if (!bearerToken) {
        logger.warn('Rejecting CodeAPI request without bearer token', authLogMeta(req, { mode }));
        return res.status(401).json({ error: 'Bearer token is required' });
      }
      principal = await jwtProvider.verify(req);
    }

    if (!principal) {
      logger.warn('CodeAPI auth provider returned no principal', authLogMeta(req, { mode }));
      return res.status(401).json({ error: 'Authentication is required' });
    }
    /* agent_run relies on the hardened sandbox path: the egress gateway writes
     * output owner bindings from the sealed grant, and internal service auth
     * keys those bindings. Without both, agent_run is unavailable. */
    if (principal.agentRun && !(env.HARDENED_SANDBOX_MODE && internalServiceAuthEnabled())) {
      logger.warn('JWT auth failure request: agent_run_unavailable', authLogMeta(req, { mode, reason: 'agent_run_unavailable' }));
      return res.status(401).json({ error: 'Invalid bearer token' });
    }
    applyPrincipal(req, principal);
    if (principal.agentRun?.fileDelete && !fileDeleteRequestMatches(req, principal)) {
      logger.warn(
        'Refusing deletion-only agent_run token outside its signed target',
        authLogMeta(req, { mode }),
      );
      return res.status(403).json({ error: 'Token is limited to one file deletion' });
    }
    logger.debug('CodeAPI request authenticated', authLogMeta(req, { mode }));
    next();
  } catch (error) {
    if (error instanceof CodeApiJwtAuthError) {
      if (error.reason === 'config') {
        logger.error(
          `JWT auth configuration failure request from ${req.ip}: ${error.message}`,
          authLogMeta(req, { reason: error.reason, error }),
        );
        return res.status(500).json({ error: 'CodeAPI JWT auth is misconfigured' });
      }
      logger.warn(
        `JWT auth failure request from ${req.ip}: ${error.reason}`,
        authLogMeta(req, { reason: error.reason }),
      );
      return res.status(401).json({ error: 'Invalid bearer token' });
    }
    if (error instanceof AuthProviderConfigError) {
      logger.error(
        `Auth provider configuration failure request from ${req.ip}: ${error.message}`,
        authLogMeta(req, { error }),
      );
      return res.status(500).json({ error: 'CodeAPI auth provider is misconfigured' });
    }
    logger.error(`CodeAPI authentication error request from ${req.ip}:`, authLogMeta(req, { error }));
    return res.status(401).json({ error: 'Authentication is required' });
  }
};

/**
 * Verify the requester is authorized to read the given storage session.
 *
 * Looks up the cached sessionKey for `session_id` (set at upload time
 * by `/upload` or `/upload/batch`) and compares it to the sessionKey
 * the requester would derive from their auth context plus the
 * `kind`/`id`/`version?` URL query params. Equality is the entire
 * authorization check — for shared kinds (`'skill'`, `'agent'`) any
 * user in the same tenant who supplies the matching kind/id/version
 * resolves the same key and is authorized; for `'user'` only the
 * uploading user does.
 */
export const sessionAuth = async (req: AuthenticatedRequest, res: Response, next: NextFunction): Promise<void | Response> => {
  const { session_id, fileId } = req.params as { session_id?: string; fileId?: string };

  if (!isValidId(session_id)) {
    logger.error(`Invalid session ID: ${session_id}`);
    return res.status(400).json({ error: 'Bad request' });
  } else if (fileId != null && fileId.length > 0 && !isValidId(fileId)) {
    logger.error(`Invalid file ID: ${fileId}`);
    return res.status(400).json({ error: 'Bad request' });
  }

  const principal = req.codeApiPrincipal;
  const agentRunPrincipal = principal?.agentRun ? principal : undefined;
  const userId = req.codeApiAuthContext?.userId ?? '';
  if (!agentRunPrincipal && !userId) {
    logger.warn('Rejecting session auth without authContext.userId', authLogMeta(req));
    return res.status(401).json({ error: 'User not found' });
  }

  const { kind, id, version } = req.query;
  if (kind !== undefined && typeof kind !== 'string') {
    logger.warn('Rejecting session auth with malformed kind query', authLogMeta(req));
    return res.status(400).json({ error: 'Bad request' });
  }
  if (id !== undefined && typeof id !== 'string') {
    logger.warn('Rejecting session auth with malformed id query', authLogMeta(req));
    return res.status(400).json({ error: 'Bad request' });
  }
  if (version !== undefined && typeof version !== 'string') {
    logger.warn('Rejecting session auth with malformed version query', authLogMeta(req));
    return res.status(400).json({ error: 'Bad request' });
  }

  let sessionKeyInput;
  try {
    sessionKeyInput = parseUploadSessionKeyInput({
      kind: kind as string | undefined,
      id: id as string | undefined,
      version: version as string | undefined,
      authContextUserId: userId,
    });
  } catch (err) {
    if (logSessionKeyResolutionError(err, res, req, 'sessionAuth: parseUploadSessionKeyInput')) {
      return;
    }
    throw err;
  }

  let sessionKey: string;
  try {
    sessionKey = resolveSessionKey(req, sessionKeyInput);
  } catch (err) {
    if (logSessionKeyResolutionError(err, res, req, 'sessionAuth: resolveSessionKey')) {
      return;
    }
    throw err;
  }
  /* C1: shared skill objects are read-only for an Agent; it deletes only its
   * own run's private objects. */
  if (agentRunPrincipal && req.method === 'DELETE' && sessionKeyInput.kind !== 'agent') {
    logger.warn('Refusing agent_run deletion outside its private run key', authLogMeta(req));
    return res.status(403).json({ error: 'Unauthorized' });
  }
  const cachedSessionKey = await connection.get(`session:${session_id}`);
  if (cachedSessionKey !== sessionKey) {
    /* The session cache expires after SESSION_CACHE_TTL. A deletion-only
     * agent_run token may then still delete, but only against the durable
     * owner binding stored with the bytes: the file server removes the object
     * only if that binding names this tenant, Agent and run. A present but
     * different cache entry is a refusal. */
    if (cachedSessionKey === null && agentRunPrincipal?.agentRun.fileDelete && req.method === 'DELETE') {
      req.sessionKey = sessionKey;
      req.ownerBindingExpectation = ownerBindingValue(agentRunPrincipal.tenantId, agentRunPrincipal.agentRun);
      logger.info('Session cache absent; deleting against the durable owner binding', authLogMeta(req));
      next();
      return;
    }
    logger.error(`Unauthorized download: Cached session key: ${sessionKeyForLog(cachedSessionKey)} | Expected session key: ${sessionKeyForLog(sessionKey)} | Session ID: ${session_id} | File ID: ${fileId}`);
    return res.status(403).json({ error: 'Unauthorized' });
  }

  req.sessionKey = sessionKey;
  next();
};
