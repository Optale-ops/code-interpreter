import type { NextFunction, Response } from 'express';
import type { AuthenticatedRequest } from '../types';
import { applyPrincipal } from './principal';
import {
    externalFetchPolicyDigest,
    loadExternalFetchPolicy,
    serializeExternalFetchPolicy,
    type ExternalFetchPolicySnapshot,
} from '../external-fetch-policy';

let cachedPolicyPath = '';
let cachedPolicyBinding:
    | {
          networkPolicy: ExternalFetchPolicySnapshot;
          networkPolicyDigest: string;
      }
    | undefined;

function localNetworkPolicyBinding(): {
    networkPolicy?: ExternalFetchPolicySnapshot;
    networkPolicyDigest?: string;
} {
    const policyPath =
        process.env.CODEAPI_LOCAL_NETWORK_POLICY_FILE?.trim() ?? '';
    if (!policyPath) return {};
    if (!cachedPolicyBinding || cachedPolicyPath !== policyPath) {
        const policy = loadExternalFetchPolicy(policyPath);
        cachedPolicyPath = policyPath;
        cachedPolicyBinding = {
            networkPolicy: serializeExternalFetchPolicy(policy),
            networkPolicyDigest: externalFetchPolicyDigest(policy),
        };
    }
    return cachedPolicyBinding;
}

export function applyLocalPrincipal(req: AuthenticatedRequest): void {
  req.planId = 'local-plan';
  /* Mirror the populate that prod auth does so sessionKey resolvers
   * have a stable userId while local mode bypasses external auth. */
  applyPrincipal(req, {
    userId: 'local-test-user',
    tenantId: 'local',
    principalSource: 'none',
    credentialId: 'local-test-key',
        ...localNetworkPolicyBinding(),
  });
}

export const localAuth = async (
  req: AuthenticatedRequest,
  _res: Response,
  next: NextFunction,
): Promise<void> => {
  applyLocalPrincipal(req);
  next();
};
