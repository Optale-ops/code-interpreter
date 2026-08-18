import { afterEach, beforeEach, describe, expect, test } from 'bun:test';
import crypto from 'node:crypto';
import fs from 'node:fs';
import net from 'node:net';
import os from 'node:os';
import path from 'node:path';

const HELPER_DIR = path.resolve(__dirname, '../helpers');
const SOCKET_PATH = '/tmp/tcs.sock';
const workspaces: string[] = [];
let server: net.Server | undefined;
let relayCalls = 0;

function responseForBody(body: string): Buffer {
  if (body.includes('/denied')) {
    const payload = JSON.stringify({
      error: 'CONTENT_TYPE_REJECTED',
      message: 'External fetch content type is not allowed',
    });
    return Buffer.from(
      [
        'HTTP/1.1 415 Unsupported Media Type',
        'Content-Type: application/json',
        `Content-Length: ${Buffer.byteLength(payload)}`,
        'Connection: close',
        '',
        payload,
      ].join('\r\n'),
    );
  }
  if (body.includes('/disconnect')) {
    return Buffer.from(
      [
        'HTTP/1.1 200 OK',
        'Content-Type: application/pdf',
        'X-CodeAPI-Egress-Host: allowed.test',
        'X-CodeAPI-Egress-Redirects: 0',
        'Transfer-Encoding: chunked',
        'Trailer: X-CodeAPI-Egress-Outcome',
        '',
        '7',
        'partial',
      ].join('\r\n'),
    );
  }
  const outcome = body.includes('/oversize') ? 'RESPONSE_TOO_LARGE' : 'OK';
  const fixture = body.includes('/oversize') ? 'partial' : 'pdf fixture';
  return Buffer.from(
    [
      'HTTP/1.1 200 OK',
      'Content-Type: application/pdf',
      'X-CodeAPI-Egress-Host: allowed.test',
      'X-CodeAPI-Egress-Redirects: 1',
      'Transfer-Encoding: chunked',
      'Trailer: X-CodeAPI-Egress-Outcome',
      'Connection: close',
      '',
      fixture.length.toString(16),
      fixture,
      '0',
      `X-CodeAPI-Egress-Outcome: ${outcome}`,
      '',
      '',
    ].join('\r\n'),
  );
}

async function startRelay(): Promise<void> {
  try {
    fs.unlinkSync(SOCKET_PATH);
  } catch {
    /* absent socket */
  }
  server = net.createServer(socket => {
    let request = '';
    socket.on('data', chunk => {
      request += chunk.toString('utf8');
      const split = request.indexOf('\r\n\r\n');
      if (split < 0) return;
      const lengthMatch = request
        .slice(0, split)
        .match(/\r\nContent-Length: (\d+)/i);
      const length = Number(lengthMatch?.[1] ?? 0);
      const body = request.slice(split + 4);
      if (Buffer.byteLength(body) < length) return;
      relayCalls += 1;
      socket.end(responseForBody(body));
    });
  });
  const listening = Promise.withResolvers<void>();
  server.listen(SOCKET_PATH, listening.resolve);
  await listening.promise;
}

async function runPython(
  code: string,
): Promise<{ status: number; stdout: string; stderr: string }> {
  const child = Bun.spawn(['python3', '-c', code], {
    env: {
      ...process.env,
      PYTHONPATH: HELPER_DIR,
      SANDBOX_EGRESS_GRANT: 'opaque-grant',
    },
    stdout: 'pipe',
    stderr: 'pipe',
  });
  const [status, stdout, stderr] = await Promise.all([
    child.exited,
    new Response(child.stdout).text(),
    new Response(child.stderr).text(),
  ]);
  return { status, stdout, stderr };
}

beforeEach(async () => {
  relayCalls = 0;
  await startRelay();
});

afterEach(async () => {
  if (server) {
    const closed = Promise.withResolvers<void>();
    server.close(() => closed.resolve());
    await closed.promise;
    server = undefined;
  }
  try {
    fs.unlinkSync(SOCKET_PATH);
  } catch {
    /* absent socket */
  }
  for (const workspace of workspaces.splice(0))
    fs.rmSync(workspace, { recursive: true, force: true });
});

function workspace(): string {
  const created = fs.mkdtempSync('/mnt/data/sandbox-fetch-helper-');
  workspaces.push(created);
  return created;
}

describe('sandbox_fetch typed helper', () => {
  test('streams to a mode-0600 file, hashes it, and returns only bounded metadata', async () => {
    const root = workspace();
    const output = path.join(root, 'download.pdf');
    const marker = 'UNIQUE_QUERY_MARKER_733';
    const code = [
      'import json',
      'from sandbox_fetch import sandbox_fetch',
      `print(json.dumps(sandbox_fetch("https://allowed.test/success?token=${marker}", ${JSON.stringify(
        output,
      )}), sort_keys=True))`,
    ].join(';');
    const result = await runPython(code);

    expect(result.status, result.stderr).toBe(0);
    expect(result.stderr).toBe('');
    expect(result.stdout).not.toContain(marker);
    expect(JSON.parse(result.stdout)).toEqual({
      host: 'allowed.test',
      bytes: 11,
      content_type: 'application/pdf',
      sha256: crypto.createHash('sha256').update('pdf fixture').digest('hex'),
      redirects: 1,
    });
    expect(fs.readFileSync(output, 'utf8')).toBe('pdf fixture');
    expect(fs.statSync(output).mode & 0o777).toBe(0o600);
    expect(fs.readdirSync(root)).toEqual(['download.pdf']);
  });

  test.each([
    ['relative.pdf'],
    ['/mnt/data'],
    ['/tmp/outside.pdf'],
    ['/mnt/data/../tmp/traversal.pdf'],
    ['/mnt/data/bad\0name.pdf'],
  ])(
    'rejects invalid output path %s without contacting the relay',
    async output => {
      const code = [
        'from sandbox_fetch import sandbox_fetch',
        `sandbox_fetch("https://allowed.test/success", ${JSON.stringify(
          output,
        )})`,
      ].join(';');
      const result = await runPython(code);
      expect(result.status).not.toBe(0);
      expect(result.stdout).toBe('');
      expect(result.stderr).not.toContain('https://');
      expect(relayCalls).toBe(0);
    },
  );

  test('rejects symlink and existing-target races without replacing either target', async () => {
    const root = workspace();
    const victim = path.join(root, 'victim.pdf');
    const symlink = path.join(root, 'symlink.pdf');
    fs.writeFileSync(victim, 'keep');
    fs.symlinkSync(victim, symlink);

    for (const output of [victim, symlink]) {
      const result = await runPython(
        [
          'from sandbox_fetch import sandbox_fetch',
          `sandbox_fetch("https://allowed.test/success", ${JSON.stringify(
            output,
          )})`,
        ].join(';'),
      );
      expect(result.status).not.toBe(0);
      expect(result.stderr).not.toContain('https://');
    }
    expect(fs.readFileSync(victim, 'utf8')).toBe('keep');
    expect(fs.lstatSync(symlink).isSymbolicLink()).toBe(true);
    expect(relayCalls).toBe(0);
  });

  test.each([
    ['/oversize', 'RESPONSE_TOO_LARGE'],
    ['/disconnect', 'FETCH_FAILED'],
    ['/denied', 'CONTENT_TYPE_REJECTED'],
  ])('removes partial output after %s', async (route, code) => {
    const root = workspace();
    const output = path.join(root, 'download.pdf');
    const result = await runPython(
      [
        'from sandbox_fetch import sandbox_fetch',
        `sandbox_fetch("https://allowed.test${route}?secret=UNIQUE_MARKER", ${JSON.stringify(
          output,
        )})`,
      ].join(';'),
    );
    expect(result.status).not.toBe(0);
    expect(result.stdout).toBe('');
    expect(result.stderr).toContain(code);
    expect(result.stderr).not.toContain('UNIQUE_MARKER');
    expect(fs.existsSync(output)).toBe(false);
    expect(fs.readdirSync(root)).toEqual([]);
  });

  test('accepts CLI URL only on stdin and emits the same metadata contract', async () => {
    const root = workspace();
    const output = path.join(root, 'cli.pdf');
    const child = Bun.spawn(
      [
        'python3',
        path.join(HELPER_DIR, 'sandbox_fetch.py'),
        '--output',
        output,
        '--url-stdin',
      ],
      {
        env: { ...process.env, SANDBOX_EGRESS_GRANT: 'opaque-grant' },
        stdin: 'pipe',
        stdout: 'pipe',
        stderr: 'pipe',
      },
    );
    child.stdin.write('https://allowed.test/success?secret=CLI_MARKER');
    child.stdin.end();
    const [status, stdout, stderr] = await Promise.all([
      child.exited,
      new Response(child.stdout).text(),
      new Response(child.stderr).text(),
    ]);
    expect(status, stderr).toBe(0);
    expect(stdout).not.toContain('CLI_MARKER');
    expect(JSON.parse(stdout)).toMatchObject({
      host: 'allowed.test',
      bytes: 11,
    });
    expect(fs.readFileSync(output, 'utf8')).toBe('pdf fixture');
  });
});
