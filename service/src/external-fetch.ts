import { promises as dns } from 'node:dns';
import fs from 'node:fs';
import type { IncomingHttpHeaders, IncomingMessage } from 'node:http';
import https from 'node:https';
import type { RequestOptions } from 'node:https';
import type { Writable } from 'node:stream';
import { ExternalFetchError } from './external-fetch-errors';
import {
  validateExternalFetchUrl,
  validateHttpsPassthroughUrl,
  validateResolvedAddresses,
} from './external-fetch-policy';
import type {
  ExternalFetchHostPolicy,
  ExternalFetchPolicy,
  ResolvedExternalAddress,
  ValidatedExternalFetchUrl,
} from './external-fetch-policy';

const USER_AGENT = 'Optale-CodeAPI-External-Fetch/1';
const STATIC_HOP_BY_HOP_HEADERS: ReadonlySet<string> = new Set([
  'connection',
  'keep-alive',
  'proxy-authenticate',
  'proxy-authorization',
  'proxy-connection',
  'te',
  'trailer',
  'transfer-encoding',
  'upgrade',
  'host',
]);
const PROCESS_TRUSTED_CA = process.env.NODE_EXTRA_CA_CERTS
  ? fs.readFileSync(process.env.NODE_EXTRA_CA_CERTS)
  : undefined;

export interface ExternalFetchResolver {
  resolve4(hostname: string): Promise<string[]>;
  resolve6(hostname: string): Promise<string[]>;
  resolveCname(hostname: string): Promise<string[]>;
}

function isNoDnsData(error: unknown): boolean {
  if (!error || typeof error !== 'object' || !('code' in error)) return false;
  return error.code === 'ENODATA' || error.code === 'ENOTFOUND';
}

async function optionalDnsAnswers(
  resolve: () => Promise<string[]>,
): Promise<string[]> {
  try {
    return await resolve();
  } catch (error) {
    if (isNoDnsData(error)) return [];
    throw new ExternalFetchError('FETCH_FAILED');
  }
}

export async function resolveExternalFetchAddresses(
  hostname: string,
  resolver: ExternalFetchResolver = dns,
): Promise<ResolvedExternalAddress[]> {
  let target = hostname;
  for (let depth = 0; depth <= 8; depth += 1) {
    const cnames = await optionalDnsAnswers(() =>
      resolver.resolveCname(target),
    );
    if (cnames.length === 0) break;
    if (cnames.length !== 1 || depth === 8)
      throw new ExternalFetchError('FETCH_FAILED');
    const next = cnames[0]?.toLowerCase().replace(/\.$/, '') ?? '';
    if (
      next.length < 1 ||
      next.length > 253 ||
      !/^[a-z0-9.-]+$/.test(next) ||
      next.split('.').some(label => label.length < 1 || label.length > 63)
    ) {
      throw new ExternalFetchError('FETCH_FAILED');
    }
    target = next;
  }

  const [ipv4, ipv6] = await Promise.all([
    optionalDnsAnswers(() => resolver.resolve4(target)),
    optionalDnsAnswers(() => resolver.resolve6(target)),
  ]);
  const seen = new Set<string>();
  const addresses: ResolvedExternalAddress[] = [];
  for (const [family, values] of [
    [4, ipv4],
    [6, ipv6],
  ] as const) {
    for (const address of values) {
      const key = `${family}:${address}`;
      if (seen.has(key)) continue;
      seen.add(key);
      addresses.push({ address, family });
    }
  }
  return validateResolvedAddresses(addresses);
}

export interface OpenExternalFetchArgs {
  url: string;
  policy: ExternalFetchPolicy;
  resolver?: ExternalFetchResolver;
  fetchCount?: number;
}

export interface OpenExternalFetchResponse {
  response: IncomingMessage;
  target: ValidatedExternalFetchUrl;
  contentType: string;
  declaredBytes?: number;
  responseBytes: number;
  redirects: number;
  timedOut: () => boolean;
  close: () => void;
}

interface PinnedHop {
  response: IncomingMessage;
  timedOut: () => boolean;
  close: () => void;
}

async function requestPinnedHop(
  target: ValidatedExternalFetchUrl,
  addresses: ResolvedExternalAddress[],
  deadlineAt: number,
): Promise<PinnedHop> {
  const result = Promise.withResolvers<IncomingMessage>();
  let timedOut = false;
  let settled = false;
  let connectTimer: NodeJS.Timeout | undefined;
  let headersTimer: NodeJS.Timeout | undefined;
  const request = https.request(buildPinnedRequestOptions(target, addresses));
  const totalTimer = setTimeout(
    () => {
      timedOut = true;
      request.destroy(new Error('external fetch total timeout'));
    },
    Math.max(1, deadlineAt - Date.now()),
  );

  const clearPreResponseTimers = (): void => {
    clearTimeout(connectTimer);
    clearTimeout(headersTimer);
  };
  const handleError = (): void => {
    clearPreResponseTimers();
    if (!settled) {
      settled = true;
      clearTimeout(totalTimer);
      result.reject(
        new ExternalFetchError(timedOut ? 'FETCH_TIMEOUT' : 'FETCH_FAILED'),
      );
    }
  };
  request.once('socket', socket => {
    socket.on('error', handleError);
    connectTimer = setTimeout(() => {
      timedOut = true;
      request.destroy(new Error('external fetch connect timeout'));
    }, target.policy.limits.connectTimeoutMs);
    socket.once('secureConnect', () => {
      clearTimeout(connectTimer);
      headersTimer = setTimeout(() => {
        timedOut = true;
        request.destroy(new Error('external fetch headers timeout'));
      }, target.policy.limits.headersTimeoutMs);
    });
  });
  request.once('response', response => {
    settled = true;
    clearPreResponseTimers();
    result.resolve(response);
  });
  request.on('error', handleError);
  request.end();

  const response = await result.promise;
  return {
    response,
    timedOut: () => timedOut,
    close: () => {
      clearPreResponseTimers();
      clearTimeout(totalTimer);
      if (!response.complete) response.destroy();
    },
  };
}

function redirectLocation(response: IncomingMessage): string | undefined {
  const values: string[] = [];
  for (let index = 0; index < response.rawHeaders.length; index += 2) {
    if (response.rawHeaders[index]?.toLowerCase() === 'location') {
      values.push(response.rawHeaders[index + 1] ?? '');
    }
  }
  if (values.length === 0) return undefined;
  if (values.length !== 1 || !values[0])
    throw new ExternalFetchError('REDIRECT_REJECTED');
  return values[0];
}

export async function openExternalFetch(
  args: OpenExternalFetchArgs,
): Promise<OpenExternalFetchResponse> {
  const startedAt = Date.now();
  let rawUrl = args.url;
  let redirects = 0;

  for (;;) {
    let target: ValidatedExternalFetchUrl;
    try {
      target = validateExternalFetchUrl(rawUrl, args.policy);
    } catch (error) {
      if (redirects > 0) throw new ExternalFetchError('REDIRECT_REJECTED');
      throw error;
    }
    let addresses: ResolvedExternalAddress[];
    if (
      args.fetchCount !== undefined &&
      args.fetchCount > target.policy.limits.maxFetchesPerGrant
    ) {
      throw new ExternalFetchError('FETCH_BUDGET_EXCEEDED');
    }
    try {
      addresses = await resolveExternalFetchAddresses(
        target.host,
        args.resolver,
      );
    } catch (error) {
      if (redirects > 0) throw new ExternalFetchError('REDIRECT_REJECTED');
      throw error;
    }
    const deadlineAt = startedAt + target.policy.limits.totalTimeoutMs;
    if (Date.now() >= deadlineAt) throw new ExternalFetchError('FETCH_TIMEOUT');
    const hop = await requestPinnedHop(target, addresses, deadlineAt);
    const status = hop.response.statusCode ?? 0;
    if ([301, 302, 303, 307, 308].includes(status)) {
      let location: string | undefined;
      try {
        location = redirectLocation(hop.response);
      } catch {
        hop.close();
        throw new ExternalFetchError('REDIRECT_REJECTED');
      }
      if (!location || redirects >= target.policy.limits.maxRedirects) {
        hop.close();
        throw new ExternalFetchError('REDIRECT_REJECTED');
      }
      if (
        Buffer.byteLength(location, 'utf8') > 8_192 ||
        /[\u0000-\u001f\u007f\\]/.test(location)
      ) {
        hop.close();
        throw new ExternalFetchError('REDIRECT_REJECTED');
      }
      let redirected: URL;
      try {
        redirected = new URL(location, target.url);
      } catch {
        hop.close();
        throw new ExternalFetchError('REDIRECT_REJECTED');
      }
      hop.close();
      rawUrl = redirected.href;
      redirects += 1;
      continue;
    }
    if (status !== 200) {
      hop.close();
      throw new ExternalFetchError('FETCH_FAILED');
    }
    try {
      const validatedHeaders = validateExternalFetchResponseHeaders(
        hop.response.headers,
        target.policy,
      );
      return {
        response: hop.response,
        target,
        contentType: validatedHeaders.contentType,
        declaredBytes: validatedHeaders.declaredBytes,
        responseBytes: 0,
        redirects,
        timedOut: hop.timedOut,
        close: hop.close,
      };
    } catch (error) {
      hop.close();
      throw error;
    }
  }
}

export interface OpenHttpsPassthroughArgs {
  url: string;
  policy: ExternalFetchPolicy;
  method: string;
  headers: Record<string, string>;
  body: Buffer;
  resolver?: ExternalFetchResolver;
  fetchCount?: number;
}

export interface OpenHttpsPassthroughResponse {
  response: IncomingMessage;
  target: ValidatedExternalFetchUrl;
  responseBytes: number;
  timedOut: () => boolean;
  close: () => void;
}

function passthroughRequestHeaders(
  input: Record<string, string>,
  bodyBytes: number,
): Record<string, string> {
  const connectionTokens = new Set(
    (input.connection ?? '')
      .split(',')
      .map(value => value.trim().toLowerCase())
      .filter(Boolean),
  );
  const headers: Record<string, string> = {};
  for (const [name, value] of Object.entries(input)) {
    const lower = name.toLowerCase();
    if (
      STATIC_HOP_BY_HOP_HEADERS.has(lower)
      || connectionTokens.has(lower)
      || lower.startsWith('x-codeapi-egress-')
      || lower === 'content-length'
    ) {
      continue;
    }
    headers[lower] = value;
  }
  headers['content-length'] = String(bodyBytes);
  headers.connection = 'close';
  return headers;
}

async function requestPinnedPassthrough(
  target: ValidatedExternalFetchUrl,
  addresses: ResolvedExternalAddress[],
  args: Pick<OpenHttpsPassthroughArgs, 'method' | 'headers' | 'body'>,
): Promise<OpenHttpsPassthroughResponse> {
  const result = Promise.withResolvers<IncomingMessage>();
  let timedOut = false;
  let settled = false;
  let connectTimer: NodeJS.Timeout | undefined;
  let headersTimer: NodeJS.Timeout | undefined;
  const deadlineAt = Date.now()
    + (target.policy.httpsPassthroughTotalTimeoutMs
      ?? target.policy.limits.totalTimeoutMs);
  const request = https.request({
    ...buildPinnedRequestOptions(target, addresses),
    method: args.method,
    headers: passthroughRequestHeaders(args.headers, args.body.length),
  });
  const totalTimer = setTimeout(() => {
    timedOut = true;
    request.destroy(new Error('HTTPS passthrough total timeout'));
  }, Math.max(1, deadlineAt - Date.now()));
  const clearPreResponseTimers = (): void => {
    clearTimeout(connectTimer);
    clearTimeout(headersTimer);
  };
  const handleError = (): void => {
    clearPreResponseTimers();
    if (!settled) {
      settled = true;
      clearTimeout(totalTimer);
      result.reject(new ExternalFetchError(timedOut ? 'FETCH_TIMEOUT' : 'FETCH_FAILED'));
    }
  };
  request.once('socket', socket => {
    socket.on('error', handleError);
    connectTimer = setTimeout(() => {
      timedOut = true;
      request.destroy(new Error('HTTPS passthrough connect timeout'));
    }, target.policy.limits.connectTimeoutMs);
    socket.once('secureConnect', () => {
      clearTimeout(connectTimer);
      headersTimer = setTimeout(() => {
        timedOut = true;
        request.destroy(new Error('HTTPS passthrough headers timeout'));
      }, target.policy.limits.headersTimeoutMs);
    });
  });
  request.once('response', response => {
    settled = true;
    clearPreResponseTimers();
    result.resolve(response);
  });
  request.on('error', handleError);
  request.end(args.body);

  const response = await result.promise;
  return {
    response,
    target,
    responseBytes: 0,
    timedOut: () => timedOut,
    close: () => {
      clearPreResponseTimers();
      clearTimeout(totalTimer);
      if (!response.complete) response.destroy();
    },
  };
}

export async function openHttpsPassthrough(
  args: OpenHttpsPassthroughArgs,
): Promise<OpenHttpsPassthroughResponse> {
  const target = validateHttpsPassthroughUrl(args.url, args.policy);
  const addresses = await resolveExternalFetchAddresses(target.host, args.resolver);
  return requestPinnedPassthrough(target, addresses, args);
}

export async function pipeHttpsPassthroughBody(
  opened: OpenHttpsPassthroughResponse,
  destination: Writable,
  maxBytes = opened.target.policy.limits.maxResponseBytes,
): Promise<number> {
  opened.responseBytes = 0;
  try {
    for await (const chunk of opened.response) {
      const bytes = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
      opened.responseBytes += bytes.length;
      if (opened.responseBytes > maxBytes) {
        throw new ExternalFetchError(
          maxBytes < opened.target.policy.limits.maxResponseBytes
            ? 'FETCH_BUDGET_EXCEEDED'
            : 'RESPONSE_TOO_LARGE',
        );
      }
      if (destination.destroyed || destination.writableEnded) {
        throw new ExternalFetchError('FETCH_FAILED');
      }
      if (!destination.write(bytes)) await waitForDrainOrClose(destination);
    }
    return opened.responseBytes;
  } catch (error) {
    if (error instanceof ExternalFetchError) throw error;
    throw new ExternalFetchError(opened.timedOut() ? 'FETCH_TIMEOUT' : 'FETCH_FAILED');
  } finally {
    opened.close();
  }
}

function waitForDrainOrClose(destination: Writable): Promise<void> {
  if (destination.destroyed || destination.writableEnded) {
    return Promise.reject(new ExternalFetchError('FETCH_FAILED'));
  }
  const result = Promise.withResolvers<void>();
  const cleanup = (): void => {
    destination.off('drain', onDrain);
    destination.off('close', onClose);
    destination.off('error', onError);
  };
  const onDrain = (): void => {
    cleanup();
    result.resolve();
  };
  const onClose = (): void => {
    cleanup();
    result.reject(new ExternalFetchError('FETCH_FAILED'));
  };
  const onError = (): void => {
    cleanup();
    result.reject(new ExternalFetchError('FETCH_FAILED'));
  };
  destination.once('drain', onDrain);
  destination.once('close', onClose);
  destination.once('error', onError);
  return result.promise;
}

export async function pipeExternalFetchBody(
  opened: OpenExternalFetchResponse,
  destination: Writable,
  maxBytes = opened.target.policy.limits.maxResponseBytes,
): Promise<number> {
  opened.responseBytes = 0;
  try {
    for await (const chunk of opened.response) {
      const bytes = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
      opened.responseBytes += bytes.length;
      if (opened.responseBytes > maxBytes) {
        throw new ExternalFetchError(
          maxBytes < opened.target.policy.limits.maxResponseBytes
            ? 'FETCH_BUDGET_EXCEEDED'
            : 'RESPONSE_TOO_LARGE',
        );
      }
      if (destination.destroyed || destination.writableEnded) {
        throw new ExternalFetchError('FETCH_FAILED');
      }
      if (!destination.write(bytes)) await waitForDrainOrClose(destination);
    }
    if (
      opened.declaredBytes !== undefined &&
      opened.responseBytes !== opened.declaredBytes
    ) {
      throw new ExternalFetchError('FETCH_FAILED');
    }
    return opened.responseBytes;
  } catch (error) {
    if (error instanceof ExternalFetchError) throw error;
    throw new ExternalFetchError(
      opened.timedOut() ? 'FETCH_TIMEOUT' : 'FETCH_FAILED',
    );
  } finally {
    opened.close();
  }
}
export function buildPinnedRequestOptions(
  target: ValidatedExternalFetchUrl,
  addresses: ResolvedExternalAddress[],
): RequestOptions {
  const pinnedAddresses = addresses.toSorted((left, right) => left.family - right.family);
  const selected = pinnedAddresses[0];
  if (!selected) throw new ExternalFetchError('FETCH_FAILED');
  return {
    protocol: 'https:',
    hostname: target.host,
    servername: target.host,
    port: 443,
    method: 'GET',
    path: `${target.url.pathname}${target.url.search}`,
    headers: {
      Accept: Array.from(target.policy.contentTypes).join(', '),
      'Accept-Encoding': 'identity',
      'User-Agent': USER_AGENT,
    },
    agent: false,
    autoSelectFamily: pinnedAddresses.length > 1,
    ...(PROCESS_TRUSTED_CA ? { ca: PROCESS_TRUSTED_CA } : {}),
    lookup: (_hostname, options, callback): void => {
      if (options.all) {
        callback(null, pinnedAddresses);
        return;
      }
      callback(null, selected.address, selected.family);
    },
  };
}

function singleHeader(
  headers: IncomingHttpHeaders | Record<string, string | string[] | undefined>,
  name: string,
): string | undefined {
  const value = headers[name];
  if (Array.isArray(value)) throw new ExternalFetchError('FETCH_FAILED');
  return value;
}

export function validateExternalFetchResponseHeaders(
  headers: IncomingHttpHeaders | Record<string, string | string[] | undefined>,
  hostPolicy: ExternalFetchHostPolicy,
): { contentType: string; declaredBytes?: number } {
  const rawType = singleHeader(headers, 'content-type');
  if (!rawType) throw new ExternalFetchError('CONTENT_TYPE_REJECTED');
  const contentType = rawType.split(';', 1)[0]?.trim().toLowerCase() ?? '';
  if (!hostPolicy.contentTypes.has(contentType)) {
    throw new ExternalFetchError('CONTENT_TYPE_REJECTED');
  }

  const contentEncoding = singleHeader(headers, 'content-encoding');
  if (contentEncoding && contentEncoding.trim().toLowerCase() !== 'identity') {
    throw new ExternalFetchError('CONTENT_TYPE_REJECTED');
  }

  const rawLength = singleHeader(headers, 'content-length');
  if (rawLength === undefined) return { contentType };
  if (!/^\d+$/.test(rawLength)) throw new ExternalFetchError('FETCH_FAILED');
  const declaredBytes = Number(rawLength);
  if (!Number.isSafeInteger(declaredBytes))
    throw new ExternalFetchError('FETCH_FAILED');
  if (declaredBytes > hostPolicy.limits.maxResponseBytes) {
    throw new ExternalFetchError('RESPONSE_TOO_LARGE');
  }
  return { contentType, declaredBytes };
}
