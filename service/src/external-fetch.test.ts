import { describe, expect, test } from 'bun:test';
import type { LookupAddress } from 'node:dns';
import {
  buildPinnedRequestOptions,
  validateExternalFetchResponseHeaders,
} from './external-fetch';
import { ExternalFetchError } from './external-fetch-errors';
import {
  parseExternalFetchPolicy,
  validateExternalFetchUrl,
} from './external-fetch-policy';

const HOST = 'temp.4d4f16c61d89ec64e760039c4ec50717.r2.cloudflarestorage.com';
const POLICY = parseExternalFetchPolicy({
  version: 1,
  limits: {
    maxRedirects: 3,
    maxResponseBytes: 26_214_400,
    maxAggregateBytesPerGrant: 52_428_800,
    maxFetchesPerGrant: 8,
    connectTimeoutMs: 3_000,
    headersTimeoutMs: 5_000,
    totalTimeoutMs: 15_000,
  },
  hosts: {
    [HOST]: { contentTypes: ['application/pdf'] },
  },
});

function expectCode(fn: () => unknown, code: ExternalFetchError['code']): void {
  try {
    fn();
    throw new Error('expected external fetch error');
  } catch (error) {
    expect(error).toBeInstanceOf(ExternalFetchError);
    expect((error as ExternalFetchError).code).toBe(code);
  }
}

describe('pinned external GET request', () => {
  test('pins the validated address while retaining exact hostname for TLS and Host', async () => {
    const validated = validateExternalFetchUrl(
      `https://${HOST}/signed.pdf?token=secret`,
      POLICY,
    );
    const options = buildPinnedRequestOptions(validated, {
      address: '93.184.216.34',
      family: 4,
    });

    expect(options.method).toBe('GET');
    expect(options.hostname).toBe(HOST);
    expect(options.servername).toBe(HOST);
    expect(options.port).toBe(443);
    expect(options.path).toBe('/signed.pdf?token=secret');
    expect(options.headers).toEqual({
      Accept: 'application/pdf',
      'Accept-Encoding': 'identity',
      'User-Agent': 'Optale-CodeAPI-External-Fetch/1',
    });
    expect(options.agent).toBe(false);

    const lookup = options.lookup;
    expect(lookup).toBeFunction();
    const selectedAddress = Promise.withResolvers<LookupAddress>();
    lookup?.(HOST, { all: false }, (error, address, family) => {
      if (error) return selectedAddress.reject(error);
      if (typeof address !== 'string')
        return selectedAddress.reject(
          new Error('lookup returned an address list'),
        );
      if (family !== 4 && family !== 6)
        return selectedAddress.reject(new Error('lookup returned no family'));
      selectedAddress.resolve({ address, family });
    });
    const selected = await selectedAddress.promise;
    expect(selected).toEqual({ address: '93.184.216.34', family: 4 });

    const selectedAddresses = Promise.withResolvers<LookupAddress[]>();
    lookup?.(HOST, { all: true }, (error, addresses) => {
      if (error) return selectedAddresses.reject(error);
      if (!Array.isArray(addresses))
        return selectedAddresses.reject(
          new Error('lookup returned one address'),
        );
      selectedAddresses.resolve(addresses);
    });
    await expect(selectedAddresses.promise).resolves.toEqual([
      { address: '93.184.216.34', family: 4 },
    ]);
  });

  test('never accepts caller headers, body, proxy, or method inputs', () => {
    const validated = validateExternalFetchUrl(
      `https://${HOST}/file.pdf`,
      POLICY,
    );
    const options = buildPinnedRequestOptions(validated, {
      address: '93.184.216.34',
      family: 4,
    });
    expect(Object.keys(options)).not.toContainAnyValues([
      'body',
      'proxy',
      'rejectUnauthorized',
    ]);
    expect(
      Object.keys(options.headers ?? {})
        .map(key => key.toLowerCase())
        .sort(),
    ).toEqual(['accept', 'accept-encoding', 'user-agent']);
  });
});

describe('external response header validation', () => {
  const hostPolicy = POLICY.hosts.get(HOST)!;

  test('accepts the configured type after lower-casing and parameter stripping', () => {
    expect(
      validateExternalFetchResponseHeaders(
        {
          'content-type': 'Application/PDF; charset=binary',
          'content-length': '42',
          'content-encoding': 'identity',
        },
        hostPolicy,
      ),
    ).toEqual({ contentType: 'application/pdf', declaredBytes: 42 });
  });

  const unsafeHeaders: Array<
    [Record<string, string | string[] | undefined>, ExternalFetchError['code']]
  > = [
    [{}, 'CONTENT_TYPE_REJECTED'],
    [{ 'content-type': 'text/html' }, 'CONTENT_TYPE_REJECTED'],
    [{ 'content-type': 'application/octet-stream' }, 'CONTENT_TYPE_REJECTED'],
    [
      { 'content-type': 'application/pdf', 'content-encoding': 'gzip' },
      'CONTENT_TYPE_REJECTED',
    ],
    [
      { 'content-type': 'application/pdf', 'content-length': '26214401' },
      'RESPONSE_TOO_LARGE',
    ],
    [
      {
        'content-type': 'application/pdf',
        'content-length': 'not-a-number',
      },
      'FETCH_FAILED',
    ],
    [
      { 'content-type': 'application/pdf', 'content-length': ['1', '2'] },
      'FETCH_FAILED',
    ],
  ];

  test.each(unsafeHeaders)(
    'rejects unsafe response headers %#',
    (headers, code) => {
      expectCode(
        () => validateExternalFetchResponseHeaders(headers, hostPolicy),
        code,
      );
    },
  );
});
