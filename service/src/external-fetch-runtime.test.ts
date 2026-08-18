/**
 * Runtime parity test for the controlled-egress fetch engine.
 *
 * `external-fetch-boundary.test.ts` runs the same real-DNS/real-TLS boundary
 * fixture under Bun. Production does NOT run Bun: the gateway ships as a
 * pre-bundled CJS artifact executed by Node (service/Dockerfile.egress-gateway
 * `production` stage), because the /external-fetch route depends on two
 * behaviours Bun's node:http/node:https compat layer does not carry
 * faithfully — HTTP response trailers and the connection-pinning
 * `https.request({ lookup })` hook that IS the SSRF defence.
 *
 * So the SSRF-critical path is exercised twice: once under Bun (developer
 * runtime) and once here, bundled exactly the way the image bundles it and
 * executed by Node, so a Bun/Node divergence in DNS pinning, redirect
 * revalidation, header allow-listing, timeouts, or streaming ceilings fails a
 * check instead of shipping.
 *
 * Skipped automatically when `node` isn't on PATH or the platform isn't Linux
 * (the fixture needs `unshare --net` to own its loopback addresses).
 */
import { afterAll, expect, test } from 'bun:test';
import { spawnSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { privateNetnsAvailable } from './external-fetch-netns';

const NODE_AVAILABLE = (() => {
  try {
    return spawnSync('node', ['--version'], { stdio: 'ignore' }).status === 0;
  } catch {
    return false;
  }
})();
const SHOULD_RUN = NODE_AVAILABLE && process.platform === 'linux' && privateNetnsAvailable();
if (!SHOULD_RUN) {
  console.warn(
    '[external-fetch-runtime] skipping: needs Linux, `node` on PATH, and unprivileged `unshare --user --net`',
  );
}
const testIfRuntime = SHOULD_RUN ? test : test.skip;

const workdir = fs.mkdtempSync(
  path.join(os.tmpdir(), 'external-fetch-runtime-'),
);

afterAll(() => {
  fs.rmSync(workdir, { recursive: true, force: true });
});

testIfRuntime(
  'crosses the same real boundaries when bundled and run under the production Node runtime',
  async () => {
    const serviceDir = path.resolve(__dirname, '..');
    const fixture = path.resolve(
      __dirname,
      'external-fetch-boundary.fixture.ts',
    );
    const fixtureDir = path.resolve(serviceDir, 'test-fixtures/external-fetch');
    const bundle = path.join(workdir, 'external-fetch-boundary.cjs');

    const build = Bun.spawnSync(
      [
        'bun',
        'build',
        fixture,
        '--target=node',
        '--format=cjs',
        `--outfile=${bundle}`,
      ],
      { cwd: serviceDir, stdout: 'pipe', stderr: 'pipe' },
    );
    expect(build.exitCode, build.stderr.toString()).toBe(0);
    expect(fs.existsSync(bundle)).toBe(true);

    const child = Bun.spawn(
      ['unshare', '--user', '--map-root-user', '--net', 'node', bundle],
      {
        cwd: serviceDir,
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
  },
  60_000,
);
