import { expect, test } from 'bun:test';
import path from 'node:path';

test('terminates CONNECT under the production Node runtime', async () => {
    const serviceDir = path.resolve(__dirname, '..');
    const fixture = path.resolve(__dirname, 'package-proxy-runtime.fixture.ts');
    const bundle = path.resolve(
        serviceDir,
        '.build/package-proxy-runtime.fixture.cjs',
    );
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
    const child = Bun.spawnSync(['node', bundle], {
        cwd: serviceDir,
        stdout: 'pipe',
        stderr: 'pipe',
        timeout: 20_000,
    });
    expect(child.exitCode, child.stderr.toString()).toBe(0);
    expect(child.stdout.toString()).toContain('PACKAGE_PROXY_TLS_RUNTIME_OK');
}, 30_000);
