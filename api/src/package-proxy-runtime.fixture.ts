import assert from 'node:assert/strict';
import fsp from 'node:fs/promises';
import http from 'node:http';
import net from 'node:net';
import os from 'node:os';
import path from 'node:path';
import tls from 'node:tls';
import {
    createPackageProxyCertificateAuthority,
    startPackageProxy,
} from './package-proxy';

async function main(): Promise<void> {
    const stateDir = await fsp.mkdtemp(
        path.join(os.tmpdir(), 'package-proxy-runtime-'),
    );
    const socketPath = path.join(stateDir, 'relay.sock');
    const calls: Array<Record<string, unknown>> = [];
    const relay = http.createServer((req, res) => {
        const chunks: Buffer[] = [];
        req.on('data', chunk => chunks.push(Buffer.from(chunk)));
        req.on('end', () => {
            calls.push(JSON.parse(Buffer.concat(chunks).toString('utf8')));
            res.writeHead(200, {
                'Content-Type': 'application/octet-stream',
                'X-CodeAPI-Network-Policy-Digest': 'P'.repeat(43),
                'X-CodeAPI-Egress-Requests': '7',
                'X-CodeAPI-Egress-Bytes': '2048',
                Trailer: 'X-CodeAPI-Egress-Outcome',
                'Transfer-Encoding': 'chunked',
            });
            res.write('package-bytes');
            res.addTrailers({ 'X-CodeAPI-Egress-Outcome': 'OK' });
            res.end();
        });
    });
    await new Promise<void>((resolve, reject) => {
        relay.once('error', reject);
        relay.listen(socketPath, resolve);
    });
    const ca = await createPackageProxyCertificateAuthority(stateDir);
    const proxy = await startPackageProxy({
        port: 0,
        relaySocketPath: socketPath,
        grant: 'opaque-grant',
        stateDir,
        caCertPath: ca.certPath,
        caKeyPath: ca.keyPath,
        log: { log() {}, warn() {}, error() {} },
    });
    const socket = net.connect(proxy.port, proxy.host);
    await new Promise<void>((resolve, reject) => {
        socket.once('connect', resolve);
        socket.once('error', reject);
    });
    socket.write(
        'CONNECT registry.npmjs.org:443 HTTP/1.1\r\nHost: registry.npmjs.org:443\r\n\r\n',
    );
    const connectResponse = await new Promise<string>((resolve, reject) => {
        const chunks: Buffer[] = [];
        const onData = (chunk: Buffer): void => {
            chunks.push(Buffer.from(chunk));
            const text = Buffer.concat(chunks).toString('utf8');
            if (!text.includes('\r\n\r\n')) return;
            socket.off('data', onData);
            resolve(text);
        };
        socket.on('data', onData);
        socket.once('error', reject);
    });
    assert.match(connectResponse, /200 Connection Established/);
    const secure = tls.connect({
        socket,
        servername: 'registry.npmjs.org',
        ca: await fsp.readFile(ca.certPath),
        rejectUnauthorized: true,
    });
    await new Promise<void>((resolve, reject) => {
        secure.once('secureConnect', resolve);
        secure.once('error', reject);
    });
    const response = await new Promise<string>((resolve, reject) => {
        const chunks: Buffer[] = [];
        secure.on('data', chunk => chunks.push(Buffer.from(chunk)));
        secure.on('end', () => resolve(Buffer.concat(chunks).toString('utf8')));
        secure.on('error', reject);
        secure.write(
            'GET /pkg HTTP/1.1\r\nHost: registry.npmjs.org\r\nAuthorization: Bearer secret\r\nConnection: close\r\n\r\n',
        );
    });
    assert.match(response, /package-bytes/);
    assert.deepEqual(proxy.summary(), {
        requestCount: 7,
        responseBytes: 2048,
        policyDigest: 'P'.repeat(43),
    });
    assert.deepEqual(calls, [
        {
            url: 'https://registry.npmjs.org/pkg',
            method: 'GET',
            headers: {},
        },
    ]);
    await proxy.close();
    await new Promise<void>(resolve => relay.close(() => resolve()));
    console.log('PACKAGE_PROXY_TLS_RUNTIME_OK');
}

void main().catch(error => {
    console.error(error);
    process.exit(1);
});
