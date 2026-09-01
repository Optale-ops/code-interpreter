import { afterAll, expect, test } from 'bun:test';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';

const workdir = fs.mkdtempSync(path.join(os.tmpdir(), 'egress-gateway-socket-'));

afterAll(() => {
  fs.rmSync(workdir, { recursive: true, force: true });
});

test('returns a structured connect error and remains available for the next request', async () => {
  const serviceDir = path.resolve(__dirname, '..');
  const fixture = path.resolve(__dirname, 'egress-gateway-socket.fixture.ts');
  const bundle = path.join(workdir, 'egress-gateway-socket.cjs');
  const build = Bun.spawnSync([
    'bun',
    'build',
    fixture,
    '--target=node',
    '--format=cjs',
    `--outfile=${bundle}`,
  ], { cwd: serviceDir, stdout: 'pipe', stderr: 'pipe' });
  expect(build.exitCode, build.stderr.toString()).toBe(0);

  const child = Bun.spawn(['node', bundle], {
    cwd: serviceDir,
    env: {
      ...process.env,
      CODEAPI_EXTERNAL_FETCH_POLICY_FILE: path.join(
        serviceDir,
        'config/external-fetch-policy.json',
      ),
    },
    stdout: 'pipe',
    stderr: 'pipe',
  });
  const [status, stdout, stderr] = await Promise.all([
    child.exited,
    new Response(child.stdout).text(),
    new Response(child.stderr).text(),
  ]);

  expect(status, stderr).toBe(0);
  expect(stdout).toContain('EGRESS_GATEWAY_SOCKET_FAILURE_SURVIVED');
}, 15_000);
