import { expect, test } from 'bun:test';
import path from 'node:path';
import { privateNetnsAvailable } from './external-fetch-netns';

const NETNS = privateNetnsAvailable();
if (!NETNS) {
  console.warn('[external-fetch-boundary] skipping: this host denies unprivileged `unshare --user --net`');
}

(NETNS ? test : test.skip)('crosses real DNS, TLS, pinned-IP, redirect, header, timeout, and oversize boundaries', async () => {
  const fixture = path.resolve(__dirname, 'external-fetch-boundary.fixture.ts');
  const fixtureDir = path.resolve(__dirname, '../test-fixtures/external-fetch');
  const child = Bun.spawn(
    ['unshare', '--user', '--map-root-user', '--net', 'bun', 'run', fixture],
    {
      cwd: path.resolve(__dirname, '..'),
      env: {
        ...process.env,
        NODE_EXTRA_CA_CERTS: path.join(fixtureDir, 'cert.pem'),
        EXTERNAL_FETCH_TLS_FIXTURE_DIR: fixtureDir,
      },
      stdout: 'pipe',
      stderr: 'pipe',
    },
  );
  const [status, stdout, stderr] = await Promise.all([
    child.exited,
    new Response(child.stdout).text(),
    new Response(child.stderr).text(),
  ]);
  expect(status, stderr).toBe(0);
  expect(stdout).toContain('EXTERNAL_FETCH_TLS_BOUNDARY_OK');
}, 30_000);
