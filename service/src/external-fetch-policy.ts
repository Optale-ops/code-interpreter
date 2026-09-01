import crypto from 'node:crypto';
import fs from 'node:fs';
import { BlockList, isIP } from 'node:net';
import { ExternalFetchError } from './external-fetch-errors';

export interface ExternalFetchLimits {
  maxRedirects: number;
  maxResponseBytes: number;
  maxAggregateBytesPerGrant: number;
  maxFetchesPerGrant: number;
  connectTimeoutMs: number;
  headersTimeoutMs: number;
  totalTimeoutMs: number;
}

export interface ExternalFetchHostPolicy {
  contentTypes: Set<string>;
  httpsPassthrough: boolean;
  httpsPassthroughTotalTimeoutMs?: number;
    packageTransport: boolean;
  limits: ExternalFetchLimits;
}

export interface ExternalFetchPolicySnapshotHost {
    contentTypes?: string[];
    httpsPassthrough?: true;
    httpsPassthroughTotalTimeoutMs?: number;
    packageTransport?: true;
    limits: ExternalFetchLimits;
}

export interface ExternalFetchPolicySnapshot {
    version: 1;
    limits: ExternalFetchLimits;
    hosts: Record<string, ExternalFetchPolicySnapshotHost>;
}

export interface ExternalFetchPolicy {
  version: 1;
  limits: ExternalFetchLimits;
  hosts: Map<string, ExternalFetchHostPolicy>;
}

export interface ValidatedExternalFetchUrl {
  url: URL;
  host: string;
  pathHash: string;
  queryPresent: boolean;
  policy: ExternalFetchHostPolicy;
}

export interface ResolvedExternalAddress {
  address: string;
  family: 4 | 6;
}

export const HARD_HTTPS_PASSTHROUGH_TOTAL_TIMEOUT_MS = 300_000;

export const HARD_EXTERNAL_FETCH_LIMITS: Readonly<ExternalFetchLimits> =
  Object.freeze({
    maxRedirects: 3,
    maxResponseBytes: 26_214_400,
    maxAggregateBytesPerGrant: 52_428_800,
    maxFetchesPerGrant: 8,
    connectTimeoutMs: 3_000,
    headersTimeoutMs: 5_000,
    totalTimeoutMs: 15_000,
  });

const LIMIT_KEYS: readonly (keyof ExternalFetchLimits)[] = [
  'maxRedirects',
  'maxResponseBytes',
  'maxAggregateBytesPerGrant',
  'maxFetchesPerGrant',
  'connectTimeoutMs',
  'headersTimeoutMs',
  'totalTimeoutMs',
];

const ALLOWED_CONTENT_TYPES: Record<string, true> = {
  'application/pdf': true,
  'text/plain': true,
  'text/csv': true,
  'text/tab-separated-values': true,
  'application/json': true,
  'application/vnd.openxmlformats-officedocument.wordprocessingml.document': true,
  'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet': true,
  'application/vnd.openxmlformats-officedocument.presentationml.presentation': true,
  'image/jpeg': true,
  'image/png': true,
  'image/webp': true,
};

const IPV4_DENY = new BlockList();
for (const [network, prefix] of [
  ['0.0.0.0', 8],
  ['10.0.0.0', 8],
  ['100.64.0.0', 10],
  ['127.0.0.0', 8],
  ['169.254.0.0', 16],
  ['172.16.0.0', 12],
  ['192.0.0.0', 24],
  ['192.0.2.0', 24],
  ['192.88.99.0', 24],
  ['192.168.0.0', 16],
  ['198.18.0.0', 15],
  ['198.51.100.0', 24],
  ['203.0.113.0', 24],
  ['224.0.0.0', 4],
  ['240.0.0.0', 4],
] as const) {
  IPV4_DENY.addSubnet(network, prefix, 'ipv4');
}

const IPV6_DENY = new BlockList();
for (const [network, prefix] of [
  ['::', 128],
  ['::1', 128],
  ['::ffff:0:0', 96],
  ['64:ff9b::', 96],
  ['64:ff9b:1::', 48],
  ['100::', 64],
  ['2001::', 32],
  ['2001:2::', 48],
  ['2001:10::', 28],
  ['2001:20::', 28],
  ['2001:db8::', 32],
  ['2002::', 16],
  ['3fff::', 20],
  ['5f00::', 16],
  ['fc00::', 7],
  ['fe80::', 10],
  ['fec0::', 10],
  ['ff00::', 8],
] as const) {
  IPV6_DENY.addSubnet(network, prefix, 'ipv6');
}

let configuredDenyCidrsRaw: string | undefined;
let configuredIpv4Deny = new BlockList();
let configuredIpv6Deny = new BlockList();

function configuredExternalFetchDenyLists(): {
  ipv4: BlockList;
  ipv6: BlockList;
} {
  const raw = process.env.CODEAPI_EXTERNAL_FETCH_DENY_CIDRS ?? '';
  if (raw === configuredDenyCidrsRaw) {
    return { ipv4: configuredIpv4Deny, ipv6: configuredIpv6Deny };
  }
  const ipv4 = new BlockList();
  const ipv6 = new BlockList();
  for (const token of raw.split(',').map(value => value.trim()).filter(Boolean)) {
    const separator = token.lastIndexOf('/');
    const address = separator > 0 ? token.slice(0, separator) : '';
    const rawPrefix = separator > 0 ? token.slice(separator + 1) : '';
    const family = isIP(address);
    const prefix = Number(rawPrefix);
    const maxPrefix = family === 4 ? 32 : family === 6 ? 128 : 0;
    if (!/^\d{1,3}$/.test(rawPrefix) || !Number.isInteger(prefix) || prefix < 0 || prefix > maxPrefix) {
      throw new Error(`CODEAPI_EXTERNAL_FETCH_DENY_CIDRS contains invalid CIDR ${token}`);
    }
    try {
      if (family === 4) ipv4.addSubnet(address, prefix, 'ipv4');
      else if (family === 6) ipv6.addSubnet(address, prefix, 'ipv6');
      else throw new Error('invalid address');
    } catch {
      throw new Error(`CODEAPI_EXTERNAL_FETCH_DENY_CIDRS contains invalid CIDR ${token}`);
    }
  }
  configuredDenyCidrsRaw = raw;
  configuredIpv4Deny = ipv4;
  configuredIpv6Deny = ipv6;
  return { ipv4, ipv6 };
}

export function validateExternalFetchDenyCidrsConfiguration(): void {
  configuredExternalFetchDenyLists();
}

function objectValue(value: unknown, label: string): Record<string, unknown> {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) {
    throw new Error(`${label} must be an object`);
  }
  return value as Record<string, unknown>;
}

function assertOnlyKeys(
  value: Record<string, unknown>,
  allowed: readonly string[],
  label: string,
): void {
  for (const key of Object.keys(value)) {
    if (!allowed.includes(key))
      throw new Error(`${label} contains unsupported key ${key}`);
  }
}

function positiveInteger(
  value: unknown,
  label: string,
  ceiling: number,
): number {
  if (
    typeof value !== 'number' ||
    !Number.isSafeInteger(value) ||
    value < 1 ||
    value > ceiling
  ) {
        throw new Error(
            `${label} must be an integer from 1 through ${ceiling}`,
        );
  }
  return value;
}

function parseLimits(
  value: unknown,
  ceiling: Readonly<ExternalFetchLimits>,
  label: string,
  requireAll: boolean,
): ExternalFetchLimits {
  const raw = objectValue(value, label);
  assertOnlyKeys(raw, LIMIT_KEYS, label);
  const parsed = { ...ceiling };
  for (const key of LIMIT_KEYS) {
    if (!(key in raw)) {
      if (requireAll) throw new Error(`${label}.${key} is required`);
      continue;
    }
        parsed[key] = positiveInteger(
            raw[key],
            `${label}.${key}`,
            ceiling[key],
        );
  }
  return parsed;
}

function validatePolicyHostname(host: string): void {
  if (
    host.length < 1 ||
    host.length > 253 ||
    host !== host.trim() ||
    host !== host.toLowerCase() ||
    !/^[\x00-\x7f]+$/.test(host) ||
    host.endsWith('.') ||
    host.includes('*') ||
    isIP(host) !== 0
  ) {
    throw new Error(
      'External fetch policy host must be a lower-case ASCII exact hostname',
    );
  }
  const labels = host.split('.');
  if (
    labels.length < 2 ||
    labels.some(
      label =>
        label.length < 1 ||
        label.length > 63 ||
        !/^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$/.test(label),
    )
  ) {
    throw new Error('External fetch policy host is invalid');
  }
}

export function parseExternalFetchPolicy(value: unknown): ExternalFetchPolicy {
  const raw = objectValue(value, 'External fetch policy');
    assertOnlyKeys(
        raw,
        ['version', 'limits', 'hosts'],
        'External fetch policy',
    );
  if (raw.version !== 1)
    throw new Error('External fetch policy version must be 1');
  const limits = parseLimits(
    raw.limits,
    HARD_EXTERNAL_FETCH_LIMITS,
    'External fetch policy limits',
    true,
  );
  const rawHosts = objectValue(raw.hosts, 'External fetch policy hosts');
  const hosts = new Map<string, ExternalFetchHostPolicy>();

  for (const [host, hostValue] of Object.entries(rawHosts)) {
    validatePolicyHostname(host);
    const rawHost = objectValue(hostValue, `External fetch host ${host}`);
    assertOnlyKeys(
      rawHost,
      [
        'contentTypes',
        'httpsPassthrough',
        'httpsPassthroughTotalTimeoutMs',
                'packageTransport',
        'limits',
      ],
      `External fetch host ${host}`,
    );
        const httpsPassthrough =
            rawHost.httpsPassthrough === undefined
      ? false
      : rawHost.httpsPassthrough === true;
    if (rawHost.httpsPassthrough !== undefined && !httpsPassthrough) {
            throw new Error(
                `External fetch host ${host} has invalid httpsPassthrough`,
            );
    }
        const packageTransport =
            rawHost.packageTransport === undefined
                ? false
                : rawHost.packageTransport === true;
        if (rawHost.packageTransport !== undefined && !packageTransport) {
            throw new Error(
                `External fetch host ${host} has invalid packageTransport`,
            );
        }
        if (
            rawHost.httpsPassthroughTotalTimeoutMs !== undefined &&
            !httpsPassthrough
        ) {
      throw new Error(
        `External fetch host ${host} cannot set httpsPassthroughTotalTimeoutMs without HTTPS passthrough`,
      );
    }
    const httpsPassthroughTotalTimeoutMs = httpsPassthrough
      ? rawHost.httpsPassthroughTotalTimeoutMs === undefined
        ? HARD_HTTPS_PASSTHROUGH_TOTAL_TIMEOUT_MS
        : positiveInteger(
            rawHost.httpsPassthroughTotalTimeoutMs,
            `External fetch host ${host}.httpsPassthroughTotalTimeoutMs`,
            HARD_HTTPS_PASSTHROUGH_TOTAL_TIMEOUT_MS,
          )
      : undefined;
        if (
            rawHost.contentTypes !== undefined &&
            !Array.isArray(rawHost.contentTypes)
        ) {
            throw new Error(
                `External fetch host ${host} contentTypes must be an array`,
            );
    }
    const rawContentTypes = rawHost.contentTypes as unknown[] | undefined;
        if (
            (rawContentTypes?.length ?? 0) < 1 &&
            !httpsPassthrough &&
            !packageTransport
        ) {
            throw new Error(
                `External fetch host ${host} must enable at least one egress scope`,
            );
    }
    const contentTypes = new Set<string>();
    for (const contentType of rawContentTypes ?? []) {
      if (
        typeof contentType !== 'string' ||
        ALLOWED_CONTENT_TYPES[contentType] !== true ||
        contentTypes.has(contentType)
      ) {
        throw new Error(
          `External fetch host ${host} has an invalid content type`,
        );
      }
      contentTypes.add(contentType);
    }
    hosts.set(host, {
      contentTypes,
      httpsPassthrough,
            packageTransport,
      ...(httpsPassthroughTotalTimeoutMs === undefined
        ? {}
        : { httpsPassthroughTotalTimeoutMs }),
      limits:
        rawHost.limits === undefined
          ? { ...limits }
          : parseLimits(
              rawHost.limits,
              limits,
              `External fetch host ${host} limits`,
              false,
            ),
    });
  }

  return { version: 1, limits, hosts };
}

export function loadExternalFetchPolicy(filePath: string): ExternalFetchPolicy {
  if (!filePath.trim())
    throw new Error('CODEAPI_EXTERNAL_FETCH_POLICY_FILE is required');
  validateExternalFetchDenyCidrsConfiguration();
  const raw = fs.readFileSync(filePath, 'utf8');
  return parseExternalFetchPolicy(JSON.parse(raw));
}

function malformedPercentEncoding(raw: string): boolean {
  for (let i = 0; i < raw.length; i += 1) {
    if (raw[i] !== '%') continue;
    if (!/^[0-9a-fA-F]{2}$/.test(raw.slice(i + 1, i + 3))) return true;
    i += 2;
  }
  return false;
}

function validatePolicyUrl(
  raw: string,
  policy: ExternalFetchPolicy,
): ValidatedExternalFetchUrl {
  if (
    typeof raw !== 'string' ||
    Buffer.byteLength(raw, 'utf8') > 8_192 ||
    !raw.startsWith('https://') ||
    /[\u0000-\u001f\u007f\\]/.test(raw) ||
    malformedPercentEncoding(raw)
  ) {
    throw new ExternalFetchError('URL_REJECTED');
  }

  const authority = raw.slice('https://'.length).split(/[/?#]/, 1)[0] ?? '';
  if (
    !authority ||
    authority.includes('@') ||
    authority.includes('%') ||
    authority.startsWith('[')
  ) {
    throw new ExternalFetchError('URL_REJECTED');
  }

  let url: URL;
  try {
    url = new URL(raw);
  } catch {
    throw new ExternalFetchError('URL_REJECTED');
  }
  if (
    url.protocol !== 'https:' ||
    (url.port !== '' && url.port !== '443') ||
    url.username !== '' ||
    url.password !== '' ||
    url.hostname.endsWith('.') ||
    isIP(url.hostname) !== 0 ||
    !/^[\x00-\x7f]+$/.test(url.hostname)
  ) {
    throw new ExternalFetchError('URL_REJECTED');
  }

  const hostPolicy = policy.hosts.get(url.hostname);
  if (!hostPolicy) throw new ExternalFetchError('HOST_NOT_ALLOWED');
  url.hash = '';
  return {
    url,
    host: url.hostname,
    pathHash: crypto
      .createHash('sha256')
      .update(url.pathname, 'utf8')
      .digest('base64url')
      .slice(0, 16),
    queryPresent: url.search.length > 0,
    policy: hostPolicy,
  };
}

export function validateExternalFetchUrl(
  raw: string,
  policy: ExternalFetchPolicy,
): ValidatedExternalFetchUrl {
  const validated = validatePolicyUrl(raw, policy);
  if (validated.policy.contentTypes.size === 0) {
    throw new ExternalFetchError('HOST_NOT_ALLOWED');
  }
  return validated;
}

export function validateHttpsPassthroughUrl(
  raw: string,
  policy: ExternalFetchPolicy,
): ValidatedExternalFetchUrl {
  const validated = validatePolicyUrl(raw, policy);
  if (!validated.policy.httpsPassthrough) {
    throw new ExternalFetchError('HOST_NOT_ALLOWED');
  }
  return validated;
}

export function validatePackageTransportUrl(
    raw: string,
    policy: ExternalFetchPolicy,
): ValidatedExternalFetchUrl {
    const validated = validatePolicyUrl(raw, policy);
    if (!validated.policy.packageTransport) {
        throw new ExternalFetchError('HOST_NOT_ALLOWED');
    }
    return validated;
}

function canonicalJson(value: unknown): string {
    if (
        value === null ||
        typeof value === 'string' ||
        typeof value === 'boolean'
    ) {
        return JSON.stringify(value);
    }
    if (typeof value === 'number') {
        if (!Number.isFinite(value))
            throw new Error('Policy contains a non-finite number');
        return JSON.stringify(value);
    }
    if (Array.isArray(value)) return `[${value.map(canonicalJson).join(',')}]`;
    if (typeof value === 'object' && value !== undefined) {
        const object = value as Record<string, unknown>;
        return `{${Object.keys(object)
            .filter(key => object[key] !== undefined)
            .sort()
            .map(key => `${JSON.stringify(key)}:${canonicalJson(object[key])}`)
            .join(',')}}`;
    }
    throw new Error('Policy contains an unsupported value');
}

export function serializeExternalFetchPolicy(
    policy: ExternalFetchPolicy,
): ExternalFetchPolicySnapshot {
    const hosts: Record<string, ExternalFetchPolicySnapshotHost> = {};
    for (const host of Array.from(policy.hosts.keys()).sort()) {
        const entry = policy.hosts.get(host);
        if (!entry) continue;
        hosts[host] = {
            ...(entry.contentTypes.size > 0
                ? { contentTypes: Array.from(entry.contentTypes).sort() }
                : {}),
            ...(entry.httpsPassthrough
                ? { httpsPassthrough: true as const }
                : {}),
            ...(entry.httpsPassthroughTotalTimeoutMs === undefined
                ? {}
                : {
                      httpsPassthroughTotalTimeoutMs:
                          entry.httpsPassthroughTotalTimeoutMs,
                  }),
            ...(entry.packageTransport
                ? { packageTransport: true as const }
                : {}),
            limits: { ...entry.limits },
        };
    }
    return { version: 1, limits: { ...policy.limits }, hosts };
}

export function externalFetchPolicyDigest(policy: ExternalFetchPolicy): string {
    return crypto
        .createHash('sha256')
        .update(canonicalJson(serializeExternalFetchPolicy(policy)), 'utf8')
        .digest('base64url');
}

export function intersectExternalFetchPolicies(
    signed: ExternalFetchPolicy,
    deployment: ExternalFetchPolicy,
): ExternalFetchPolicy {
    const limits = Object.fromEntries(
        LIMIT_KEYS.map(key => [
            key,
            Math.min(signed.limits[key], deployment.limits[key]),
        ]),
    ) as unknown as ExternalFetchLimits;
    const hosts = new Map<string, ExternalFetchHostPolicy>();
    for (const [host, requested] of signed.hosts) {
        const upper = deployment.hosts.get(host);
        if (!upper) throw new ExternalFetchError('HOST_NOT_ALLOWED');
        for (const contentType of requested.contentTypes) {
            if (!upper.contentTypes.has(contentType))
                throw new ExternalFetchError('HOST_NOT_ALLOWED');
        }
        if (requested.httpsPassthrough && !upper.httpsPassthrough) {
            throw new ExternalFetchError('HOST_NOT_ALLOWED');
        }
        if (requested.packageTransport && !upper.packageTransport) {
            throw new ExternalFetchError('HOST_NOT_ALLOWED');
        }
        const hostLimits = Object.fromEntries(
            LIMIT_KEYS.map(key => [
                key,
                Math.min(requested.limits[key], upper.limits[key], limits[key]),
            ]),
        ) as unknown as ExternalFetchLimits;
        hosts.set(host, {
            contentTypes: new Set(requested.contentTypes),
            httpsPassthrough: requested.httpsPassthrough,
            ...(requested.httpsPassthrough
                ? {
                      httpsPassthroughTotalTimeoutMs: Math.min(
                          requested.httpsPassthroughTotalTimeoutMs ??
                              HARD_HTTPS_PASSTHROUGH_TOTAL_TIMEOUT_MS,
                          upper.httpsPassthroughTotalTimeoutMs ??
                              HARD_HTTPS_PASSTHROUGH_TOTAL_TIMEOUT_MS,
                      ),
                  }
                : {}),
            packageTransport: requested.packageTransport,
            limits: hostLimits,
        });
    }
    return { version: 1, limits, hosts };
}

export function effectiveExternalFetchPolicy(
    snapshot: ExternalFetchPolicySnapshot | undefined,
    digest: string | undefined,
    deployment: ExternalFetchPolicy,
): ExternalFetchPolicy {
    if (!snapshot || !digest) throw new ExternalFetchError('HOST_NOT_ALLOWED');
    let signed: ExternalFetchPolicy;
    try {
        signed = parseExternalFetchPolicy(snapshot);
    } catch {
        throw new ExternalFetchError('HOST_NOT_ALLOWED');
    }
    if (externalFetchPolicyDigest(signed) !== digest) {
        throw new ExternalFetchError('HOST_NOT_ALLOWED');
    }
    return intersectExternalFetchPolicies(signed, deployment);
}

export function validateResolvedAddresses(
  addresses: ResolvedExternalAddress[],
): ResolvedExternalAddress[] {
  const configuredDeny = configuredExternalFetchDenyLists();
  if (addresses.length < 1 || addresses.length > 16) {
    throw new ExternalFetchError('FETCH_FAILED');
  }
  for (const { address, family } of addresses) {
    if (
      (family === 4 &&
        (isIP(address) !== 4 ||
          IPV4_DENY.check(address, 'ipv4') ||
          configuredDeny.ipv4.check(address, 'ipv4'))) ||
      (family === 6 &&
        (isIP(address) !== 6 ||
          IPV6_DENY.check(address, 'ipv6') ||
          configuredDeny.ipv6.check(address, 'ipv6'))) ||
      (family !== 4 && family !== 6)
    ) {
      throw new ExternalFetchError('ADDRESS_NOT_GLOBAL');
    }
  }
  return addresses;
}
