import fs from 'node:fs';
import fsp from 'node:fs/promises';
import http from 'node:http';
import path from 'node:path';
import crypto from 'node:crypto';
import tls from 'node:tls';
import { spawnSync } from 'node:child_process';
import type net from 'node:net';
import { writeWithBackpressure } from './http-backpressure';
import type { PackageTransportSummary } from '../../shared/package-transport';
export type { PackageTransportSummary } from '../../shared/package-transport';

const MAX_RESPONSE_BYTES = 26_214_400;
const MAX_ENVELOPE_BYTES = 65_536;
const SAFE_REQUEST_HEADERS: Record<string, true> = {
    accept: true,
    'if-modified-since': true,
    'if-none-match': true,
    range: true,
    'user-agent': true,
};
const SAFE_RESPONSE_HEADERS: Record<string, true> = {
    'accept-ranges': true,
    'cache-control': true,
    'content-disposition': true,
    'content-type': true,
    etag: true,
    expires: true,
    'last-modified': true,
};

export interface PackageProxyOptions {
    host?: string;
    port: number;
    relaySocketPath: string;
    grant: string;
    stateDir: string;
    caCertPath: string;
    caKeyPath: string;
    summaryPath?: string;
    log?: Pick<typeof console, 'error' | 'log' | 'warn'>;
}

export interface PackageProxyHandle {
    host: string;
    port: number;
    server: http.Server;
    close: () => Promise<void>;
    summary: () => PackageTransportSummary;
}

export interface PackageProxyCertificateAuthority {
    certPath: string;
    keyPath: string;
}

function runOpenSsl(args: string[]): void {
    const result = spawnSync('openssl', args, {
        stdio: ['ignore', 'ignore', 'pipe'],
    });
    if (result.status !== 0) {
        throw new Error(`OpenSSL failed: ${result.stderr.toString().trim()}`);
    }
}

export function cleanupPackageProxyState(stateDir: string): void {
    fs.rmSync(stateDir, { recursive: true, force: true });
}

export async function createPackageProxyCertificateAuthority(
    stateDir: string,
): Promise<PackageProxyCertificateAuthority> {
    await fsp.mkdir(stateDir, { recursive: true, mode: 0o700 });
    await fsp.chmod(stateDir, 0o700);
    const keyPath = path.join(stateDir, 'ca-key.pem');
    const certPath = path.join(stateDir, 'ca.pem');
    runOpenSsl([
        'req',
        '-x509',
        '-newkey',
        'rsa:2048',
        '-nodes',
        '-keyout',
        keyPath,
        '-out',
        certPath,
        '-days',
        '1',
        '-subj',
        '/CN=Optale Job Package Proxy CA',
        '-addext',
        'basicConstraints=critical,CA:TRUE',
        '-addext',
        'keyUsage=critical,keyCertSign,cRLSign',
    ]);
    await fsp.chmod(keyPath, 0o600);
    await fsp.chmod(certPath, 0o444);
    return { certPath, keyPath };
}

function leafCertificate(
    stateDir: string,
    caCertPath: string,
    caKeyPath: string,
    hostname: string,
): { cert: Buffer; key: Buffer } {
    const label = crypto
        .createHash('sha256')
        .update(hostname, 'utf8')
        .digest('hex')
        .slice(0, 24);
    const keyPath = path.join(stateDir, `leaf-${label}.key`);
    const requestPath = path.join(stateDir, `leaf-${label}.csr`);
    const certPath = path.join(stateDir, `leaf-${label}.pem`);
    if (!fs.existsSync(certPath) || !fs.existsSync(keyPath)) {
        runOpenSsl([
            'req',
            '-new',
            '-newkey',
            'rsa:2048',
            '-nodes',
            '-keyout',
            keyPath,
            '-out',
            requestPath,
            '-subj',
            `/CN=${hostname}`,
            '-addext',
            `subjectAltName=DNS:${hostname}`,
        ]);
        runOpenSsl([
            'x509',
            '-req',
            '-in',
            requestPath,
            '-CA',
            caCertPath,
            '-CAkey',
            caKeyPath,
            '-CAcreateserial',
            '-out',
            certPath,
            '-days',
            '1',
            '-sha256',
            '-copy_extensions',
            'copy',
        ]);
        fs.chmodSync(keyPath, 0o600);
        fs.chmodSync(certPath, 0o444);
        try {
            fs.unlinkSync(requestPath);
        } catch {
            /* absent request */
        }
    }
    return { cert: fs.readFileSync(certPath), key: fs.readFileSync(keyPath) };
}

function safeRequestHeaders(
    headers: http.IncomingHttpHeaders,
): Record<string, string> {
    const safe: Record<string, string> = {};
    for (const [name, value] of Object.entries(headers)) {
        const lower = name.toLowerCase();
        if (SAFE_REQUEST_HEADERS[lower] !== true || typeof value !== 'string')
            continue;
        safe[lower] = value;
    }
    return safe;
}

function normalizeRequestUrl(
    req: http.IncomingMessage,
    tunnelHost?: string,
): string {
    const raw = req.url ?? '';
    let url: URL;
    try {
        if (tunnelHost) {
            if (!raw.startsWith('/') || raw.startsWith('//'))
                throw new Error('invalid origin form');
            url = new URL(`https://${tunnelHost}${raw}`);
        } else {
            url = new URL(raw);
        }
    } catch {
        throw new Error('invalid package proxy URL');
    }
    if (
        url.protocol !== 'https:' ||
        (url.port !== '' && url.port !== '443') ||
        url.username !== '' ||
        url.password !== '' ||
        url.hostname.endsWith('.')
    ) {
        throw new Error('invalid package proxy URL');
    }
    url.hash = '';
    return url.href;
}

function writeSummary(
    pathname: string | undefined,
    summary: PackageTransportSummary,
): void {
    if (!pathname) return;
    const temporary = `${pathname}.tmp`;
    fs.writeFileSync(temporary, JSON.stringify(summary), { mode: 0o600 });
    fs.renameSync(temporary, pathname);
}

function updateSummaryFromResponse(
    response: http.IncomingMessage,
    summary: PackageTransportSummary,
    summaryPath: string | undefined,
): void {
    const requestCount = Number(
        response.trailers['x-codeapi-egress-requests'] ??
            response.headers['x-codeapi-egress-requests'],
    );
    const responseBytes = Number(
        response.trailers['x-codeapi-egress-bytes'] ??
            response.headers['x-codeapi-egress-bytes'],
    );
    const digest = response.headers['x-codeapi-network-policy-digest'];
    if (Number.isSafeInteger(requestCount) && requestCount >= 0)
        summary.requestCount = requestCount;
    if (Number.isSafeInteger(responseBytes) && responseBytes >= 0)
        summary.responseBytes = responseBytes;
    if (typeof digest === 'string' && /^[A-Za-z0-9_-]{43}$/.test(digest))
        summary.policyDigest = digest;
    writeSummary(summaryPath, summary);
}

function sendPlain(
    res: http.ServerResponse,
    status: number,
    message: string,
): void {
    res.writeHead(status, {
        'Content-Type': 'text/plain',
        Connection: 'close',
    });
    res.end(message);
}

export async function startPackageProxy(
    opts: PackageProxyOptions,
): Promise<PackageProxyHandle> {
    const log = opts.log ?? console;
    const host = opts.host ?? '127.0.0.1';
    if (host !== '127.0.0.1')
        throw new Error('Package proxy must bind IPv4 loopback');
    if (
        !opts.grant ||
        !opts.relaySocketPath ||
        !opts.caCertPath ||
        !opts.caKeyPath
    ) {
        throw new Error('Package proxy configuration is incomplete');
    }
    const summary: PackageTransportSummary = {
        requestCount: 0,
        responseBytes: 0,
        policyDigest: '',
    };
    const activeSockets = new Set<net.Socket>();
    const activeUpstreams = new Set<http.ClientRequest>();

    const forward = (
        req: http.IncomingMessage,
        res: http.ServerResponse,
        tunnelHost?: string,
    ): void => {
        const method = (req.method ?? '').toUpperCase();
        if (method !== 'GET' && method !== 'HEAD') {
            req.resume();
            sendPlain(res, 405, 'method not allowed');
            return;
        }
        if (
            req.headers['transfer-encoding'] !== undefined ||
            Number(req.headers['content-length'] ?? '0') !== 0
        ) {
            req.resume();
            sendPlain(res, 400, 'request body not allowed');
            return;
        }
        let url: string;
        try {
            url = normalizeRequestUrl(req, tunnelHost);
        } catch {
            req.resume();
            sendPlain(res, 400, 'invalid request');
            return;
        }
        const envelope = Buffer.from(
            JSON.stringify({
                url,
                method,
                headers: safeRequestHeaders(req.headers),
            }),
            'utf8',
        );
        if (envelope.length > MAX_ENVELOPE_BYTES) {
            req.resume();
            sendPlain(res, 413, 'request too large');
            return;
        }
        const upstream = http.request(
            {
                socketPath: opts.relaySocketPath,
                method: 'POST',
                path: '/package-transport',
                headers: {
                    'Content-Type': 'application/json',
                    'Content-Length': String(envelope.length),
                    'X-CodeAPI-Egress-Grant': opts.grant,
                    Connection: 'close',
                },
            },
            upstreamResponse => {
                const headers: http.OutgoingHttpHeaders = {
                    Connection: 'close',
                };
                for (const [name, value] of Object.entries(
                    upstreamResponse.headers,
                )) {
                    if (
                        value === undefined ||
                        SAFE_RESPONSE_HEADERS[name.toLowerCase()] !== true
                    )
                        continue;
                    headers[name] = value;
                }
                res.writeHead(upstreamResponse.statusCode ?? 502, headers);
                let bytes = 0;
                upstreamResponse.on('data', chunk => {
                    const buffer = Buffer.isBuffer(chunk)
                        ? chunk
                        : Buffer.from(chunk);
                    bytes += buffer.length;
                    if (bytes > MAX_RESPONSE_BYTES) {
                        upstream.destroy(
                            new Error(
                                'package proxy response exceeds hard limit',
                            ),
                        );
                        res.destroy();
                        return;
                    }
                    if (method !== 'HEAD')
                        writeWithBackpressure(upstreamResponse, res, buffer);
                });
                const abortDownstream = (): void => {
                    upstream.destroy();
                    if (!res.destroyed) res.destroy();
                };
                upstreamResponse.on('aborted', abortDownstream);
                upstreamResponse.on('error', abortDownstream);
                upstreamResponse.on('end', () => {
                    const outcome =
                        upstreamResponse.trailers['x-codeapi-egress-outcome'];
                    if (outcome !== 'OK') {
                        log.warn(
                            `package proxy rejected incomplete gateway response: ${String(outcome ?? 'missing outcome')}`,
                        );
                        abortDownstream();
                        return;
                    }
                    updateSummaryFromResponse(
                        upstreamResponse,
                        summary,
                        opts.summaryPath,
                    );
                    res.end();
                });
            },
        );
        activeUpstreams.add(upstream);
        upstream.on('close', () => activeUpstreams.delete(upstream));
        upstream.setTimeout(30_000, () =>
            upstream.destroy(new Error('package relay timeout')),
        );
        upstream.on('error', error => {
            log.error('package proxy relay error', error);
            if (!res.headersSent) sendPlain(res, 502, 'bad gateway');
            else res.destroy();
        });
        req.on('aborted', () => upstream.destroy());
        res.on('close', () => {
            if (!res.writableEnded) upstream.destroy();
        });
        upstream.end(envelope);
    };

    const tunnelHosts = new WeakMap<net.Socket, string>();
    const tunneledServer = http.createServer((req, res) => {
        const tunnelHost = tunnelHosts.get(req.socket);
        if (!tunnelHost) {
            req.resume();
            sendPlain(res, 400, 'invalid tunnel');
            return;
        }
        forward(req, res, tunnelHost);
    });
    const server = http.createServer((req, res) => forward(req, res));
    server.on('connect', (req, socket, head) => {
        const target = req.url ?? '';
        const separator = target.lastIndexOf(':');
        const targetHost = separator > 0 ? target.slice(0, separator) : '';
        const targetPort = separator > 0 ? target.slice(separator + 1) : '';
        if (
            targetPort !== '443' ||
            head.length !== 0 ||
            targetHost.length > 253 ||
            !/^[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?$/.test(targetHost) ||
            targetHost.includes('..') ||
            targetHost
                .split('.')
                .some(label => label.length < 1 || label.length > 63)
        ) {
            socket.end('HTTP/1.1 403 Forbidden\r\nConnection: close\r\n\r\n');
            return;
        }
        let certificate: { cert: Buffer; key: Buffer };
        try {
            certificate = leafCertificate(
                opts.stateDir,
                opts.caCertPath,
                opts.caKeyPath,
                targetHost,
            );
        } catch (error) {
            log.error('package proxy certificate generation failed', error);
            socket.end('HTTP/1.1 502 Bad Gateway\r\nConnection: close\r\n\r\n');
            return;
        }
        socket.write(
            'HTTP/1.1 200 Connection Established\r\nConnection: keep-alive\r\n\r\n',
        );
        const tlsServer = tls.createServer(certificate, secureSocket => {
            tunnelHosts.set(secureSocket, targetHost);
            activeSockets.add(secureSocket);
            secureSocket.on('close', () => activeSockets.delete(secureSocket));
            secureSocket.on('error', () => activeSockets.delete(secureSocket));
            tunneledServer.emit('connection', secureSocket);
        });
        tlsServer.on('tlsClientError', () => socket.destroy());
        tlsServer.emit('connection', socket);
    });
    server.maxConnections = 32;
    server.headersTimeout = 5_000;
    server.requestTimeout = 10_000;
    server.timeout = 30_000;
    server.on('connection', socket => {
        activeSockets.add(socket);
        socket.setTimeout(30_000, () => socket.destroy());
        socket.on('close', () => activeSockets.delete(socket));
        socket.on('error', () => activeSockets.delete(socket));
    });
    server.on('clientError', (_error, socket) => socket.destroy());

    await new Promise<void>((resolve, reject) => {
        server.once('error', reject);
        server.listen(opts.port, host, resolve);
    });
    const address = server.address();
    if (address == null || typeof address === 'string')
        throw new Error('Package proxy address is unavailable');
    log.log(`package proxy listening on ${host}:${address.port}`);
    return {
        host,
        port: address.port,
        server,
        summary: () => ({ ...summary }),
        close: async () => {
            for (const upstream of activeUpstreams) upstream.destroy();
            for (const socket of activeSockets) socket.destroy();
            await new Promise<void>(resolve => server.close(() => resolve()));
        },
    };
}

if (require.main === module) {
    const port = Number(process.env.PACKAGE_PROXY_PORT ?? '3129');
    let handle: PackageProxyHandle | undefined;
    let stopping = false;
    const shutdown = (): void => {
        if (stopping) return;
        stopping = true;
        if (!handle) {
            process.exit(0);
            return;
        }
        void handle.close().finally(() => process.exit(0));
    };
    process.on('SIGTERM', shutdown);
    process.on('SIGINT', shutdown);
    startPackageProxy({
        host: '127.0.0.1',
        port,
        relaySocketPath:
            process.env.PACKAGE_PROXY_RELAY_SOCKET ?? '/tmp/tcs.sock',
        grant: process.env.PACKAGE_PROXY_GRANT ?? '',
        stateDir: process.env.PACKAGE_PROXY_STATE_DIR ?? '',
        caCertPath: process.env.PACKAGE_PROXY_CA_CERT ?? '',
        caKeyPath: process.env.PACKAGE_PROXY_CA_KEY ?? '',
        summaryPath: process.env.PACKAGE_PROXY_SUMMARY_PATH,
    })
        .then(started => {
            handle = started;
            const readyPath = process.env.PACKAGE_PROXY_READY_PATH;
            if (readyPath)
                fs.writeFileSync(readyPath, 'ready', { mode: 0o600 });
        })
        .catch(error => {
            console.error('package proxy failed to start', error);
            process.exit(1);
        });
}
