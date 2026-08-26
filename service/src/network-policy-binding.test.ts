import { describe, expect, test } from 'bun:test';
import {
    HARD_EXTERNAL_FETCH_LIMITS,
    externalFetchPolicyDigest,
    parseExternalFetchPolicy,
    serializeExternalFetchPolicy,
} from './external-fetch-policy';
import { openEgressGrant, sealEgressGrant } from './egress-grant';
import { buildExecutionManifestClaims } from './execution-manifest-claims';
import {
    signExecutionManifest,
    verifyExecutionManifest,
    type ExecutionManifestClaims,
} from './execution-manifest';

const SECRET = 'network-policy-binding-secret-32-bytes';

function policyBinding() {
    const policy = parseExternalFetchPolicy({
        version: 1,
        limits: { ...HARD_EXTERNAL_FETCH_LIMITS },
        hosts: {
            'registry.npmjs.org': { packageTransport: true },
        },
    });
    return {
        network_policy: serializeExternalFetchPolicy(policy),
        network_policy_digest: externalFetchPolicyDigest(policy),
    };
}

function manifestClaims(
    overrides: Partial<ExecutionManifestClaims> = {},
): ExecutionManifestClaims {
    return {
        v: 1,
        exec_id: 'exec_123',
        tenant_id: 'tenant_abc',
        user_id: 'user_123',
        session_key: 'tenant:tenant_abc:user:user_123',
        input_files: [],
        read_sessions: [],
        output_session_id: 'sess_output',
        max_upload_bytes: 1024,
        max_output_files: 10,
        max_requests: 100,
        iat: 100,
        exp: 300,
        ...policyBinding(),
        ...overrides,
    };
}

describe('network policy binding', () => {
    test('round-trips one canonical snapshot and digest through manifest and grant', () => {
        const manifest = verifyExecutionManifest(
            signExecutionManifest(manifestClaims(), SECRET),
            SECRET,
            { nowSeconds: 150 },
        );
        const grant = openEgressGrant(
            sealEgressGrant(
                {
                    grant_id: 'grant_123',
                    ...manifest,
                },
                SECRET,
            ),
            SECRET,
            150,
        );

        expect(grant.network_policy).toEqual(manifest.network_policy);
        expect(grant.network_policy_digest).toBe(
            manifest.network_policy_digest,
        );
    });

    test('rejects a manifest whose digest does not match its snapshot', () => {
        expect(() =>
            signExecutionManifest(
                manifestClaims({
                    network_policy_digest: 'A'.repeat(43),
                }),
                SECRET,
            ),
        ).toThrow();
    });

    test('rejects a grant whose digest does not match its snapshot', () => {
        expect(() =>
            openEgressGrant(
                sealEgressGrant(
                    {
                        grant_id: 'grant_123',
                        ...manifestClaims(),
                        network_policy_digest: 'A'.repeat(43),
                    },
                    SECRET,
                ),
                SECRET,
                150,
            ),
        ).toThrow();
    });

    test('rejects a half-present policy binding', () => {
        expect(() =>
            signExecutionManifest(
                manifestClaims({
                    network_policy: undefined,
                }),
                SECRET,
            ),
        ).toThrow();
    });

    test('copies the authenticated policy binding into execution manifest claims', () => {
        const binding = policyBinding();
        const claims = buildExecutionManifestClaims({
            req: {
                codeApiAuthContext: {
                    userId: 'user_123',
                    tenantId: 'tenant_abc',
                    principalSource: 'librechat_jwt',
                    ...binding,
                    networkPolicy: binding.network_policy,
                    networkPolicyDigest: binding.network_policy_digest,
                },
            } as never,
            executionId: 'exec_123',
            userId: 'user_123',
            sessionKey: 'tenant:tenant_abc:user:user_123',
            outputSessionId: 'sess_output',
            payload: { language: 'python', version: '3.14.4', files: [] },
            nowSeconds: 100,
        });
        expect(claims.network_policy).toEqual(binding.network_policy);
        expect(claims.network_policy_digest).toBe(
            binding.network_policy_digest,
        );
    });
});
