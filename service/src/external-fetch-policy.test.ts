import { describe, expect, test } from 'bun:test';
import {
  HARD_EXTERNAL_FETCH_LIMITS,
  HARD_MAX_EXTERNAL_FETCH_HOSTS,
  externalFetchPolicyDigest,
  parseExternalFetchPolicy,
  serializeExternalFetchPolicy,
  validateExternalFetchUrl,
  validateHttpsPassthroughUrl,
  validateResolvedAddresses,
} from './external-fetch-policy';
import { ExternalFetchError } from './external-fetch-errors';

const FROZEN_HOST =
  'temp.4d4f16c61d89ec64e760039c4ec50717.r2.cloudflarestorage.com';

function frozenPolicy(overrides: Record<string, unknown> = {}): unknown {
  return {
    version: 1,
    limits: { ...HARD_EXTERNAL_FETCH_LIMITS },
    hosts: {
      [FROZEN_HOST]: {
        contentTypes: ['application/pdf'],
      },
    },
    ...overrides,
  };
}

function expectCode(fn: () => unknown, code: ExternalFetchError['code']): void {
  try {
    fn();
    throw new Error('expected external fetch error');
  } catch (error) {
    expect(error).toBeInstanceOf(ExternalFetchError);
    expect((error as ExternalFetchError).code).toBe(code);
  }
}

describe('external fetch policy parser', () => {
  test('accepts the frozen exact-host PDF policy', () => {
    const policy = parseExternalFetchPolicy(frozenPolicy());

    expect(policy.version).toBe(1);
    expect(policy.limits).toEqual(HARD_EXTERNAL_FETCH_LIMITS);
    expect(policy.hosts.get(FROZEN_HOST)).toEqual({
      contentTypes: new Set(['application/pdf']),
      httpsPassthrough: false,
            packageTransport: false,
      limits: HARD_EXTERNAL_FETCH_LIMITS,
    });
  });

  test('accepts a passthrough-only exact host without widening typed fetch', () => {
    const consoleHost = 'console-staging.optale.com';
    const policy = parseExternalFetchPolicy(
      frozenPolicy({
        hosts: {
          [FROZEN_HOST]: { contentTypes: ['application/pdf'] },
          [consoleHost]: { httpsPassthrough: true },
        },
      }),
    );

    expect(policy.hosts.get(consoleHost)).toEqual({
      contentTypes: new Set(),
      httpsPassthrough: true,
      httpsPassthroughTotalTimeoutMs: 300_000,
            packageTransport: false,
      limits: HARD_EXTERNAL_FETCH_LIMITS,
    });
    expectCode(
            () =>
                validateExternalFetchUrl(
                    `https://${consoleHost}/api/optale/mcp`,
                    policy,
                ),
      'HOST_NOT_ALLOWED',
    );
    expect(
            validateHttpsPassthroughUrl(
                `https://${consoleHost}/api/optale/mcp`,
                policy,
            ).host,
    ).toBe(consoleHost);
  });

  test('bounds the passthrough lifetime separately from PDF fetch limits', () => {
        expect(() =>
            parseExternalFetchPolicy(
      frozenPolicy({
        hosts: {
          'console-staging.optale.com': {
            httpsPassthrough: true,
            httpsPassthroughTotalTimeoutMs: 300_001,
          },
        },
      }),
            ),
        ).toThrow();
    const policy = parseExternalFetchPolicy(
      frozenPolicy({
        hosts: {
          'console-staging.optale.com': {
            httpsPassthrough: true,
            httpsPassthroughTotalTimeoutMs: 25_000,
          },
        },
      }),
    );
        expect(
            policy.hosts.get('console-staging.optale.com')
                ?.httpsPassthroughTotalTimeoutMs,
        ).toBe(25_000);
  });

    test.each([{}, { httpsPassthrough: false }, { httpsPassthrough: 'true' }])(
        'rejects a host without one enabled egress scope %#',
        hostPolicy => {
    expect(() =>
      parseExternalFetchPolicy(
                    frozenPolicy({
                        hosts: { 'console-staging.optale.com': hostPolicy },
                    }),
      ),
    ).toThrow();
        },
    );

  test.each([
    ['policy', frozenPolicy({ unexpected: true })],
    [
      'host',
      frozenPolicy({
        hosts: {
          [FROZEN_HOST]: {
            contentTypes: ['application/pdf'],
            unexpected: true,
          },
        },
      }),
    ],
  ])('rejects unknown fields on the %s shape', (_scope, value) => {
    expect(() => parseExternalFetchPolicy(value)).toThrow(/unsupported key/);
  });

  test('requires content types for an ordinary fetch host', () => {
    expect(() =>
      parseExternalFetchPolicy(
        frozenPolicy({
          hosts: {
            [FROZEN_HOST]: {
              limits: { maxResponseBytes: 1024 },
            },
          },
        }),
      ),
    ).toThrow(/must enable at least one egress scope/);
  });

  test.each([9, 64])(
    'rejects maxFetchesPerGrant=%d above the hard ceiling of 8',
    maxFetchesPerGrant => {
      expect(() =>
        parseExternalFetchPolicy(
          frozenPolicy({
            limits: {
              ...HARD_EXTERNAL_FETCH_LIMITS,
              maxFetchesPerGrant,
            },
          }),
        ),
      ).toThrow(/maxFetchesPerGrant must be an integer from 1 through 8/);
    },
  );

  test('accepts exactly 256 hosts and preserves canonical digest determinism', () => {
    const hosts = Object.fromEntries(
      Array.from({ length: HARD_MAX_EXTERNAL_FETCH_HOSTS }, (_, index) => [
        `host-${index}.example.com`,
        { contentTypes: ['application/pdf'] },
      ]),
    );
    const first = parseExternalFetchPolicy(frozenPolicy({ hosts }));
    const snapshot = serializeExternalFetchPolicy(first);
    const reparsed = parseExternalFetchPolicy(snapshot);
    expect(Object.keys(snapshot.hosts)).toHaveLength(256);
    expect(externalFetchPolicyDigest(reparsed)).toBe(
      externalFetchPolicyDigest(first),
    );
  });

  test('rejects 257 hosts in parsed and canonical snapshot inputs', () => {
    const hosts = Object.fromEntries(
      Array.from({ length: HARD_MAX_EXTERNAL_FETCH_HOSTS + 1 }, (_, index) => [
        `host-${index}.example.com`,
        { contentTypes: ['application/pdf'] },
      ]),
    );
    expect(() => parseExternalFetchPolicy(frozenPolicy({ hosts }))).toThrow(
      /at most 256 exact hosts/,
    );

    const allowed = parseExternalFetchPolicy(
      frozenPolicy({
        hosts: Object.fromEntries(Object.entries(hosts).slice(0, 256)),
      }),
    );
    allowed.hosts.set('overflow.example.com', allowed.hosts.values().next().value!);
    expect(() => serializeExternalFetchPolicy(allowed)).toThrow(
      /at most 256 exact hosts/,
    );
  });

  test('accepts an empty host map as deny-all', () => {
    const policy = parseExternalFetchPolicy(frozenPolicy({ hosts: {} }));
    expect(policy.hosts.size).toBe(0);
  });

  test.each([
    '*.r2.cloudflarestorage.com',
    'TEMP.example.com',
    ' example.com',
    'example.com ',
    'example.com.',
    'éxample.com',
    'example.com:443',
    'https://example.com',
    'example.com/path',
  ])('rejects invalid or non-exact host key %s', host => {
    expect(() =>
      parseExternalFetchPolicy(
        frozenPolicy({
          hosts: { [host]: { contentTypes: ['application/pdf'] } },
        }),
      ),
    ).toThrow();
  });

  test('rejects policy and per-host limits above hard ceilings', () => {
    expect(() =>
      parseExternalFetchPolicy(
        frozenPolicy({
          limits: { ...HARD_EXTERNAL_FETCH_LIMITS, maxRedirects: 4 },
        }),
      ),
    ).toThrow();

    expect(() =>
      parseExternalFetchPolicy(
        frozenPolicy({
          hosts: {
            [FROZEN_HOST]: {
              contentTypes: ['application/pdf'],
              limits: {
                maxResponseBytes:
                                    HARD_EXTERNAL_FETCH_LIMITS.maxResponseBytes +
                                    1,
              },
            },
          },
        }),
      ),
    ).toThrow();
  });

  test('allows per-host limits only to lower global limits', () => {
    const policy = parseExternalFetchPolicy(
      frozenPolicy({
        hosts: {
          [FROZEN_HOST]: {
            contentTypes: ['application/pdf'],
            limits: {
              maxResponseBytes: 1024,
              totalTimeoutMs: 1000,
            },
          },
        },
      }),
    );

    expect(policy.hosts.get(FROZEN_HOST)?.limits).toEqual({
      ...HARD_EXTERNAL_FETCH_LIMITS,
      maxResponseBytes: 1024,
      totalTimeoutMs: 1000,
    });
  });

  test.each([
    { contentTypes: [] },
    { contentTypes: ['application/octet-stream'] },
    { contentTypes: ['text/html'] },
    { contentTypes: ['application/pdf', 'application/pdf'] },
  ])(
    'rejects unsupported or duplicate content types $contentTypes',
    ({ contentTypes }) => {
      expect(() =>
        parseExternalFetchPolicy(
          frozenPolicy({
            hosts: { [FROZEN_HOST]: { contentTypes } },
          }),
        ),
      ).toThrow();
    },
  );
});

describe('configured external fetch CIDR exclusions', () => {
  test('rejects a globally routable address covered by production configuration', () => {
    const original = process.env.CODEAPI_EXTERNAL_FETCH_DENY_CIDRS;
    try {
      process.env.CODEAPI_EXTERNAL_FETCH_DENY_CIDRS = '93.184.216.0/24';
      expectCode(
        () => validateResolvedAddresses([{ address: '93.184.216.34', family: 4 }]),
        'ADDRESS_NOT_GLOBAL',
      );
    } finally {
      if (original === undefined) delete process.env.CODEAPI_EXTERNAL_FETCH_DENY_CIDRS;
      else process.env.CODEAPI_EXTERNAL_FETCH_DENY_CIDRS = original;
    }
  });

  test('fails closed when a configured CIDR is malformed', () => {
    const original = process.env.CODEAPI_EXTERNAL_FETCH_DENY_CIDRS;
    try {
      process.env.CODEAPI_EXTERNAL_FETCH_DENY_CIDRS = '93.184.216.0/99';
      expect(() =>
        validateResolvedAddresses([{ address: '93.184.216.34', family: 4 }]),
      ).toThrow(/CODEAPI_EXTERNAL_FETCH_DENY_CIDRS/);
    } finally {
      if (original === undefined) delete process.env.CODEAPI_EXTERNAL_FETCH_DENY_CIDRS;
      else process.env.CODEAPI_EXTERNAL_FETCH_DENY_CIDRS = original;
    }
  });
});

describe('external fetch URL validation', () => {
  const policy = parseExternalFetchPolicy(frozenPolicy());

  test('accepts one exact HTTPS host, preserves path/query, and strips fragment', () => {
    const parsed = validateExternalFetchUrl(
      `https://${FROZEN_HOST}/folder/file.pdf?X-Amz-Signature=secret#local-fragment`,
      policy,
    );

    expect(parsed.url.href).toBe(
      `https://${FROZEN_HOST}/folder/file.pdf?X-Amz-Signature=secret`,
    );
    expect(parsed.host).toBe(FROZEN_HOST);
    expect(parsed.queryPresent).toBe(true);
    expect(parsed.pathHash).toMatch(/^[A-Za-z0-9_-]{16}$/);
        expect(parsed.policy.contentTypes).toEqual(
            new Set(['application/pdf']),
        );
  });

  test.each([
    `http://${FROZEN_HOST}/file.pdf`,
    `ftp://${FROZEN_HOST}/file.pdf`,
    `ws://${FROZEN_HOST}/file.pdf`,
    `wss://${FROZEN_HOST}/file.pdf`,
    `https://${FROZEN_HOST}:444/file.pdf`,
    `https://user@${FROZEN_HOST}/file.pdf`,
    `https://user:pass@${FROZEN_HOST}/file.pdf`,
    'https://127.0.0.1/file.pdf',
    'https://[::1]/file.pdf',
    'https://2130706433/file.pdf',
    'https://0x7f000001/file.pdf',
    'https://017700000001/file.pdf',
    `https://${FROZEN_HOST}./file.pdf`,
    `https://${FROZEN_HOST}\\@evil.example/file.pdf`,
    `https://${FROZEN_HOST}/bad%zz`,
    `https://${FROZEN_HOST}/line\nbreak`,
  ])('rejects malformed or unsafe URL %s', raw => {
    expectCode(() => validateExternalFetchUrl(raw, policy), 'URL_REJECTED');
  });

  test('distinguishes a valid but unlisted exact host', () => {
    expectCode(
      () =>
                validateExternalFetchUrl(
                    'https://unlisted.example/file.pdf',
                    policy,
                ),
      'HOST_NOT_ALLOWED',
    );
  });

  test('rejects URLs longer than 8 KiB', () => {
    expectCode(
      () =>
        validateExternalFetchUrl(
          `https://${FROZEN_HOST}/${'a'.repeat(8192)}`,
          policy,
        ),
      'URL_REJECTED',
    );
  });
});

describe('external fetch address validation', () => {
  test('accepts only an all-global A/AAAA set and keeps every answer', () => {
    expect(
      validateResolvedAddresses([
        { address: '93.184.216.34', family: 4 },
        { address: '2606:2800:220:1:248:1893:25c8:1946', family: 6 },
      ]),
    ).toEqual([
      { address: '93.184.216.34', family: 4 },
      { address: '2606:2800:220:1:248:1893:25c8:1946', family: 6 },
    ]);
  });

  test.each([
    '0.0.0.0',
    '10.0.0.1',
    '100.64.0.1',
    '127.0.0.1',
    '169.254.169.254',
    '172.16.0.1',
    '192.0.2.1',
    '192.168.1.1',
    '198.18.0.1',
    '198.51.100.1',
    '203.0.113.1',
    '224.0.0.1',
    '240.0.0.1',
    '::',
    '::1',
    '::ffff:127.0.0.1',
    'fc00::1',
    'fe80::1',
    '2001:db8::1',
    'ff00::1',
  ])('rejects non-global address %s', address => {
    const family = address.includes(':') ? 6 : 4;
    expectCode(
      () => validateResolvedAddresses([{ address, family }]),
      'ADDRESS_NOT_GLOBAL',
    );
  });

  test('rejects the full answer set when one answer is private', () => {
    expectCode(
      () =>
        validateResolvedAddresses([
          { address: '93.184.216.34', family: 4 },
          { address: '10.0.0.1', family: 4 },
        ]),
      'ADDRESS_NOT_GLOBAL',
    );
  });

  test('rejects empty and amplified answer sets', () => {
    expectCode(() => validateResolvedAddresses([]), 'FETCH_FAILED');
    expectCode(
      () =>
        validateResolvedAddresses(
          Array.from({ length: 17 }, (_, index) => ({
            address: `93.184.216.${index + 1}`,
            family: 4,
          })),
        ),
      'FETCH_FAILED',
    );
  });
});
