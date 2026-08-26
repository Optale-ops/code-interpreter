import { describe, expect, test } from 'bun:test';
import {
    HARD_EXTERNAL_FETCH_LIMITS,
    effectiveExternalFetchPolicy,
    externalFetchPolicyDigest,
    intersectExternalFetchPolicies,
    parseExternalFetchPolicy,
    serializeExternalFetchPolicy,
    validatePackageTransportUrl,
} from './external-fetch-policy';
import { ExternalFetchError } from './external-fetch-errors';

const packagePolicy = (
    hosts: Record<string, unknown> = {
        'registry.npmjs.org': { packageTransport: true },
        'files.pythonhosted.org': { packageTransport: true },
    },
) => ({
    version: 1,
    limits: { ...HARD_EXTERNAL_FETCH_LIMITS },
    hosts,
});

describe('package transport policy', () => {
    test('keeps package transport distinct from typed fetch and HTTPS passthrough', () => {
        const policy = parseExternalFetchPolicy(packagePolicy());
        const host = policy.hosts.get('registry.npmjs.org');

        expect(host).toMatchObject({
            contentTypes: new Set(),
            httpsPassthrough: false,
            packageTransport: true,
        });
        expect(
            validatePackageTransportUrl(
                'https://registry.npmjs.org/pkg/-/pkg-1.0.0.tgz',
                policy,
            ).host,
        ).toBe('registry.npmjs.org');
    });

    test('serializes canonically and produces a stable base64url SHA-256 digest', () => {
        const first = parseExternalFetchPolicy(packagePolicy());
        const second = parseExternalFetchPolicy(
            packagePolicy({
                'files.pythonhosted.org': { packageTransport: true },
                'registry.npmjs.org': { packageTransport: true },
            }),
        );

        expect(serializeExternalFetchPolicy(first)).toEqual(
            serializeExternalFetchPolicy(second),
        );
        expect(externalFetchPolicyDigest(first)).toBe(
            externalFetchPolicyDigest(second),
        );
        expect(externalFetchPolicyDigest(first)).toMatch(/^[A-Za-z0-9_-]{43}$/);
    });

    test('intersects a signed subset with the deployment upper bound', () => {
        const deployment = parseExternalFetchPolicy(
            packagePolicy({
                'registry.npmjs.org': {
                    packageTransport: true,
                    limits: { maxResponseBytes: 4096, maxFetchesPerGrant: 8 },
                },
                'files.pythonhosted.org': { packageTransport: true },
            }),
        );
        const signed = parseExternalFetchPolicy(
            packagePolicy({
                'registry.npmjs.org': {
                    packageTransport: true,
                    limits: { maxResponseBytes: 2048, maxFetchesPerGrant: 4 },
                },
            }),
        );

        const effective = intersectExternalFetchPolicies(signed, deployment);
        expect(Array.from(effective.hosts.keys())).toEqual([
            'registry.npmjs.org',
        ]);
        expect(effective.hosts.get('registry.npmjs.org')?.limits).toMatchObject(
            {
                maxResponseBytes: 2048,
                maxFetchesPerGrant: 4,
            },
        );
    });

    test('rejects a signed package scope outside the deployment upper bound', () => {
        const deployment = parseExternalFetchPolicy(
            packagePolicy({
                'registry.npmjs.org': { contentTypes: ['application/json'] },
            }),
        );
        const signed = parseExternalFetchPolicy(
            packagePolicy({
                'registry.npmjs.org': { packageTransport: true },
            }),
        );

        expect(() =>
            intersectExternalFetchPolicies(signed, deployment),
        ).toThrow();
    });

    test('rejects non-HTTPS, alternate-port, IP-literal, and unlisted package URLs', () => {
        const policy = parseExternalFetchPolicy(packagePolicy());
        for (const url of [
            'http://registry.npmjs.org/pkg',
            'https://registry.npmjs.org:444/pkg',
            'https://127.0.0.1/pkg',
            'https://unlisted.example/pkg',
        ]) {
            try {
                validatePackageTransportUrl(url, policy);
                throw new Error('expected rejection');
            } catch (error) {
                expect(error).toBeInstanceOf(ExternalFetchError);
            }
        }
    });
});

describe('effective signed policy', () => {
    test('denies missing and mismatched bindings before returning a policy', () => {
        const deployment = parseExternalFetchPolicy(packagePolicy());
        const snapshot = serializeExternalFetchPolicy(deployment);
        expect(() =>
            effectiveExternalFetchPolicy(undefined, undefined, deployment),
        ).toThrow();
        expect(() =>
            effectiveExternalFetchPolicy(snapshot, 'A'.repeat(43), deployment),
        ).toThrow();
        expect(
            effectiveExternalFetchPolicy(
                snapshot,
                externalFetchPolicyDigest(deployment),
                deployment,
            ).hosts.has('registry.npmjs.org'),
        ).toBe(true);
    });
});
