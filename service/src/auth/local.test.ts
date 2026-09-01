import { afterEach, describe, expect, test } from 'bun:test';
import path from 'node:path';
import type * as t from '../types';
import { applyLocalPrincipal } from './local';

afterEach(() => {
    delete process.env.CODEAPI_LOCAL_NETWORK_POLICY_FILE;
});

describe('applyLocalPrincipal', () => {
  test('sets the local mock principal used by unauthenticated local mode', () => {
    const req = {} as t.AuthenticatedRequest;

    applyLocalPrincipal(req);

    expect(req.planId).toBe('local-plan');
    expect(req.codeApiAuthContext).toMatchObject({
      userId: 'local-test-user',
      tenantId: 'local',
      principalSource: 'none',
    });
    expect(req.codeApiPrincipal?.credentialId).toBe('local-test-key');
  });

    test('loads a signed local-only policy binding for real-boundary fixtures', () => {
        process.env.CODEAPI_LOCAL_NETWORK_POLICY_FILE = path.resolve(
            __dirname,
            '../../config/external-fetch-policy.json',
        );
        const req = {} as t.AuthenticatedRequest;
        applyLocalPrincipal(req);
        expect(req.codeApiAuthContext?.networkPolicy?.version).toBe(1);
        expect(req.codeApiAuthContext?.networkPolicyDigest).toMatch(
            /^[A-Za-z0-9_-]{43}$/,
        );
    });
});
