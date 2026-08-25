import { afterEach, describe, expect, test } from 'bun:test';
import fs from 'node:fs';
import http from 'node:http';
import net from 'node:net';
import os from 'node:os';
import path from 'node:path';

const PRELOAD = path.resolve(__dirname, '../helpers/https_passthrough_preload.cjs');
const tempDirs: string[] = [];
const servers: Array<http.Server | net.Server> = [];

afterEach(async () => {
  await Promise.all(
    servers.splice(0).map(
      server => new Promise<void>(resolve => server.close(() => resolve())),
    ),
  );
  for (const dir of tempDirs.splice(0))
    fs.rmSync(dir, { recursive: true, force: true });
});

async function listen(server: http.Server | net.Server, socketPath: string): Promise<void> {
  await new Promise<void>((resolve, reject) => {
    server.once('error', reject);
    server.listen(socketPath, () => {
      server.off('error', reject);
      resolve();
    });
  });
  servers.push(server);
}

describe('Node HTTPS passthrough preload', () => {
  test('relays HTTP URLs so the gateway returns a typed policy denial', async () => {
    const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'https-passthrough-http-'));
    tempDirs.push(tempDir);
    const socketPath = path.join(tempDir, 'relay.sock');
    const grantPath = path.join(tempDir, 'grant');
    fs.writeFileSync(grantPath, 'opaque-egress-grant', { mode: 0o400 });

    let observedUrl = '';
    const server = http.createServer(async (request, response) => {
      const chunks: Buffer[] = [];
      for await (const chunk of request)
        chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk));
      observedUrl = JSON.parse(Buffer.concat(chunks).toString('utf8')).url;
      const payload = JSON.stringify({ error: 'URL_REJECTED' });
      response.writeHead(403, {
        'Content-Type': 'application/json',
        'Content-Length': String(Buffer.byteLength(payload)),
      });
      response.end(payload);
    });
    await listen(server, socketPath);

    const childScript = "const r=await fetch('http://console-staging.optale.com/api/optale/mcp');const b=await r.json();if(r.status!==403||b.error!=='URL_REJECTED')process.exit(9);";
    const child = Bun.spawn(['node', '--eval', childScript], {
      env: {
        ...process.env,
        NODE_OPTIONS: `--require=${PRELOAD}`,
        CODEAPI_EGRESS_SOCKET_PATH: socketPath,
        CODEAPI_EGRESS_GRANT_FILE: grantPath,
      },
      stdout: 'pipe',
      stderr: 'pipe',
    });
    const [status, stderr] = await Promise.all([
      child.exited,
      new Response(child.stderr).text(),
    ]);
    expect(status, stderr).toBe(0);
    expect(observedUrl).toBe('http://console-staging.optale.com/api/optale/mcp');
  });

  test('rejects a response body whose outcome trailer reports a failed transfer', async () => {
    const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'https-passthrough-trailer-'));
    tempDirs.push(tempDir);
    const socketPath = path.join(tempDir, 'relay.sock');
    const grantPath = path.join(tempDir, 'grant');
    fs.writeFileSync(grantPath, 'opaque-egress-grant', { mode: 0o400 });

    const server = net.createServer(socket => {
      let request = Buffer.alloc(0);
      socket.on('data', chunk => {
        request = Buffer.concat([request, Buffer.from(chunk)]);
        const headerEnd = request.indexOf('\r\n\r\n');
        if (headerEnd < 0) return;
        const headerText = request.subarray(0, headerEnd).toString('utf8');
        const declared = Number(headerText.match(/\r\ncontent-length: (\d+)/i)?.[1] ?? 0);
        if (request.length - headerEnd - 4 < declared) return;
        const partial = '{"partial":';
        socket.end([
          'HTTP/1.1 200 OK',
          'Content-Type: application/json',
          'Transfer-Encoding: chunked',
          'Trailer: X-CodeAPI-Egress-Outcome',
          'Connection: close',
          '',
          partial.length.toString(16),
          partial,
          '0',
          'X-CodeAPI-Egress-Outcome: FETCH_FAILED',
          '',
          '',
        ].join('\r\n'));
      });
    });
    await listen(server, socketPath);

    const childScript = "const r=await fetch('https://console-staging.optale.com/api/optale/mcp');try{await r.text();process.exit(9)}catch{}";
    const child = Bun.spawn(['node', '--eval', childScript], {
      env: {
        ...process.env,
        NODE_OPTIONS: `--require=${PRELOAD}`,
        CODEAPI_EGRESS_SOCKET_PATH: socketPath,
        CODEAPI_EGRESS_GRANT_FILE: grantPath,
      },
      stdout: 'pipe',
      stderr: 'pipe',
    });
    const [status, stderr] = await Promise.all([
      child.exited,
      new Response(child.stderr).text(),
    ]);
    expect(status, stderr).toBe(0);
  });

  test('carries the original method, authorization header, body, and response over the grant relay', async () => {
    const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'https-passthrough-preload-'));
    tempDirs.push(tempDir);
    const socketPath = path.join(tempDir, 'relay.sock');
    const grantPath = path.join(tempDir, 'grant');
    fs.writeFileSync(grantPath, 'opaque-egress-grant', { mode: 0o400 });

    let observed: Record<string, unknown> | undefined;
    const server = http.createServer(async (request, response) => {
      const chunks: Buffer[] = [];
      for await (const chunk of request)
        chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk));
      observed = JSON.parse(Buffer.concat(chunks).toString('utf8')) as Record<string, unknown>;
      expect(request.method).toBe('POST');
      expect(request.url).toBe('/https-passthrough');
      expect(request.headers['x-codeapi-egress-grant']).toBe('opaque-egress-grant');
      response.writeHead(201, {
        'Content-Type': 'application/json',
        'X-Upstream-Marker': 'preserved',
      });
      response.end(JSON.stringify({ accepted: true }));
    });
    await listen(server, socketPath);

    const childScript = [
      "const response = await fetch('https://console-staging.optale.com/api/optale/mcp', {",
      "  method: 'POST',",
      "  headers: { Authorization: 'Bearer presence-only', 'X-Client-Marker': 'kept', 'Content-Type': 'application/json' },",
      "  body: JSON.stringify({ action: 'record_search' }),",
      "});",
      "const body = await response.json();",
      "if (response.status !== 201 || response.headers.get('x-upstream-marker') !== 'preserved' || body.accepted !== true) process.exit(9);",
    ].join('\n');
    const child = Bun.spawn(['node', '--input-type=module', '--eval', childScript], {
      env: {
        ...process.env,
        NODE_OPTIONS: `--require=${PRELOAD}`,
        CODEAPI_EGRESS_SOCKET_PATH: socketPath,
        CODEAPI_EGRESS_GRANT_FILE: grantPath,
      },
      stdout: 'pipe',
      stderr: 'pipe',
    });
    const [status, stderr] = await Promise.all([
      child.exited,
      new Response(child.stderr).text(),
    ]);

    expect(status, stderr).toBe(0);
    expect(observed).toMatchObject({
      url: 'https://console-staging.optale.com/api/optale/mcp',
      method: 'POST',
      headers: {
        authorization: 'Bearer presence-only',
        'content-type': 'application/json',
        'x-client-marker': 'kept',
      },
    });
    expect(Buffer.from(String(observed?.bodyBase64), 'base64').toString('utf8'))
      .toBe(JSON.stringify({ action: 'record_search' }));
  });
});
