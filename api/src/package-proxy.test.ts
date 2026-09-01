import { afterEach, describe, expect, test } from 'bun:test';
import fsp from 'node:fs/promises';
import http from 'node:http';
import net from 'node:net';
import os from 'node:os';
import path from 'node:path';
import {
    cleanupPackageProxyState,
    createPackageProxyCertificateAuthority,
    startPackageProxy,
    type PackageProxyHandle,
} from './package-proxy';

const handles: PackageProxyHandle[] = [];
const stateDirs: string[] = [];

afterEach(async () => {
    while (handles.length > 0) await handles.pop()!.close();
    for (const stateDir of stateDirs.splice(0))
        cleanupPackageProxyState(stateDir);
});

async function fixture(options: { outcome?: string; disconnect?: boolean } = {}): Promise<{
    stateDir: string;
    socketPath: string;
    calls: Array<{
        path: string;
        grant: string;
        body: Record<string, unknown>;
    }>;
    close: () => Promise<void>;
}> {
    const stateDir = await fsp.mkdtemp(
        path.join(os.tmpdir(), 'package-proxy-test-'),
    );
    stateDirs.push(stateDir);
    const socketPath = path.join(stateDir, 'relay.sock');
    const calls: Array<{
        path: string;
        grant: string;
        body: Record<string, unknown>;
    }> = [];
    const server = http.createServer((req, res) => {
        const chunks: Buffer[] = [];
        req.on('data', chunk => chunks.push(Buffer.from(chunk)));
        req.on('end', () => {
            calls.push({
                path: req.url ?? '',
                grant: String(req.headers['x-codeapi-egress-grant'] ?? ''),
                body: JSON.parse(Buffer.concat(chunks).toString('utf8')),
            });
            res.writeHead(200, {
                'Content-Type': 'application/octet-stream',
                'X-CodeAPI-Network-Policy-Digest': 'P'.repeat(43),
                Trailer: 'X-CodeAPI-Egress-Outcome, X-CodeAPI-Egress-Requests, X-CodeAPI-Egress-Bytes',
            });
            res.write('package-bytes');
            if (options.disconnect) {
                res.destroy();
                return;
            }
            res.addTrailers({
                'X-CodeAPI-Egress-Outcome': options.outcome ?? 'OK',
                'X-CodeAPI-Egress-Requests': '7',
                'X-CodeAPI-Egress-Bytes': '2048',
            });
            res.end();
        });
    });
    await new Promise<void>((resolve, reject) => {
        server.once('error', reject);
        server.listen(socketPath, resolve);
    });
    return {
        stateDir,
        socketPath,
        calls,
        close: () =>
            new Promise<void>(resolve => server.close(() => resolve())),
    };
}

describe('per-job package proxy', () => {
    test('turns native absolute-form proxy requests into bounded relay envelopes', async () => {
        const fx = await fixture();
        const ca = await createPackageProxyCertificateAuthority(fx.stateDir);
        const proxy = await startPackageProxy({
            host: '127.0.0.1',
            port: 0,
            relaySocketPath: fx.socketPath,
            grant: 'opaque-grant',
            stateDir: fx.stateDir,
            caCertPath: ca.certPath,
            caKeyPath: ca.keyPath,
            log: { log() {}, warn() {}, error() {} },
        });
        handles.push(proxy);

        const response = await new Promise<string>((resolve, reject) => {
            const socket = net.connect(proxy.port, proxy.host);
            const chunks: Buffer[] = [];
            socket.on('connect', () =>
                socket.write(
                    [
                        'GET https://registry.npmjs.org/pkg/-/pkg-1.0.0.tgz HTTP/1.1',
                        'Host: registry.npmjs.org',
                        'Authorization: Bearer secret',
                        'Cookie: session=secret',
                        'Proxy-Authorization: Basic secret',
                        'Accept: application/octet-stream',
                        'Connection: close',
                        '',
                        '',
                    ].join('\r\n'),
                ),
            );
            socket.on('data', chunk => chunks.push(Buffer.from(chunk)));
            socket.on('end', () =>
                resolve(Buffer.concat(chunks).toString('utf8')),
            );
            socket.on('error', reject);
        });

        expect(response).toContain('HTTP/1.1 200 OK');
        expect(response).toContain('package-bytes');
        expect(fx.calls).toHaveLength(1);
        expect(fx.calls[0].path).toBe('/package-transport');
        expect(fx.calls[0].grant).toBe('opaque-grant');
        expect(fx.calls[0].body).toEqual({
            url: 'https://registry.npmjs.org/pkg/-/pkg-1.0.0.tgz',
            method: 'GET',
            headers: { accept: 'application/octet-stream' },
        });
        expect(proxy.summary()).toEqual({
            requestCount: 7,
            responseBytes: 2048,
            policyDigest: 'P'.repeat(43),
        });
        await fx.close();
    });

    test.each(['RESPONSE_TOO_LARGE', 'FETCH_FAILED'])(
        'does not report a clean EOF when the gateway trailer is %s',
        async outcome => {
            const fx = await fixture({ outcome });
            const ca = await createPackageProxyCertificateAuthority(fx.stateDir);
            const proxy = await startPackageProxy({
                host: '127.0.0.1',
                port: 0,
                relaySocketPath: fx.socketPath,
                grant: 'opaque-grant',
                stateDir: fx.stateDir,
                caCertPath: ca.certPath,
                caKeyPath: ca.keyPath,
                log: { log() {}, warn() {}, error() {} },
            });
            handles.push(proxy);
            const completed = await new Promise<boolean>(resolve => {
                const request = http.request(
                    {
                        host: proxy.host,
                        port: proxy.port,
                        method: 'GET',
                        path: 'https://registry.npmjs.org/pkg.tgz',
                        headers: { Host: 'registry.npmjs.org' },
                    },
                    response => {
                        response.resume();
                        response.on('end', () => resolve(true));
                        response.on('aborted', () => resolve(false));
                        response.on('error', () => resolve(false));
                    },
                );
                request.on('error', () => resolve(false));
                request.end();
            });
            expect(completed).toBe(false);
            await fx.close();
        },
    );

    test('does not report a clean EOF when the gateway disconnects mid-stream', async () => {
        const fx = await fixture({ disconnect: true });
        const ca = await createPackageProxyCertificateAuthority(fx.stateDir);
        const proxy = await startPackageProxy({
            host: '127.0.0.1', port: 0, relaySocketPath: fx.socketPath,
            grant: 'opaque-grant', stateDir: fx.stateDir,
            caCertPath: ca.certPath, caKeyPath: ca.keyPath,
            log: { log() {}, warn() {}, error() {} },
        });
        handles.push(proxy);
        const completed = await new Promise<boolean>(resolve => {
            const request = http.request(
                    {
                        host: proxy.host,
                        port: proxy.port,
                        method: 'GET',
                        path: 'https://registry.npmjs.org/pkg.tgz',
                        headers: { Host: 'registry.npmjs.org' },
                    },
                    response => {
                    response.resume();
                    response.on('end', () => resolve(true));
                    response.on('aborted', () => resolve(false));
                    response.on('error', () => resolve(false));
                },
            );
            request.on('error', () => resolve(false));
                request.end();
        });
        expect(completed).toBe(false);
        await fx.close();
    });

    test('refuses opaque CONNECT tunneling and alternate ports without touching the relay', async () => {
        const fx = await fixture();
        const ca = await createPackageProxyCertificateAuthority(fx.stateDir);
        const proxy = await startPackageProxy({
            host: '127.0.0.1',
            port: 0,
            relaySocketPath: fx.socketPath,
            grant: 'opaque-grant',
            stateDir: fx.stateDir,
            caCertPath: ca.certPath,
            caKeyPath: ca.keyPath,
            log: { log() {}, warn() {}, error() {} },
        });
        handles.push(proxy);

        const raw = await new Promise<string>((resolve, reject) => {
            const socket = net.connect(proxy.port, proxy.host);
            const chunks: Buffer[] = [];
            socket.on('connect', () =>
                socket.write(
                    [
                        'CONNECT registry.npmjs.org:444 HTTP/1.1',
                        'Host: registry.npmjs.org:444',
                        '',
                        '',
                    ].join('\r\n'),
                ),
            );
            socket.on('data', chunk => chunks.push(Buffer.from(chunk)));
            socket.on('end', () =>
                resolve(Buffer.concat(chunks).toString('utf8')),
            );
            socket.on('error', reject);
        });
        expect(raw).toContain('403');
        expect(fx.calls).toHaveLength(0);
        await fx.close();
    });
});
