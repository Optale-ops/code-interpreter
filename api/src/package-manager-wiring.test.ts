import { describe, expect, test } from 'bun:test';
import fsp from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import type { NsJailResult } from './nsjail';
import {
    applyPackageManagerEnvironment,
    attachPackageSetupSummary,
    collectPackageSetupSummary,
    filterExtraEnvVars,
} from './job';

describe('native package manager wiring', () => {
    test('uses manager-native proxy and trust settings with one job-local install root', () => {
        const env: Record<string, string> = {
            PATH: '/pkgs/node/bin:/usr/bin',
            NODE_PATH: '/pkgs/node/node_modules',
        };
        applyPackageManagerEnvironment(env);

        expect(env.PIP_PROXY).toBe('http://127.0.0.1:3129');
        expect(env.PIP_CERT).toBe('/run/codeapi/package-ca.pem');
        expect(env.PIP_TARGET).toBe('/mnt/data/.optale-packages/python');
        expect(env.npm_config_https_proxy).toBe('http://127.0.0.1:3129');
        expect(env.npm_config_cafile).toBe('/run/codeapi/package-ca.pem');
        expect(env.npm_config_prefix).toBe('/mnt/data/.optale-packages/node');
        expect(env.PATH?.split(':')[0]).toBe(
            '/usr/local/lib/sandbox-fetch/package-bin',
        );
        expect(env.PATH).toContain('/mnt/data/.optale-packages/node/bin');
        expect(env.NODE_PATH).toContain(
            '/mnt/data/.optale-packages/node/node_modules',
        );
        expect(env.PYTHONPATH?.split(':')[0]).toBe(
            '/mnt/data/.optale-packages/python',
        );
        expect(env.HTTP_PROXY).toBeUndefined();
        expect(env.HTTPS_PROXY).toBeUndefined();
    });

    test('prevents caller overrides of package proxy, CA, and install roots', () => {
        expect(
            filterExtraEnvVars({
                PIP_PROXY: 'http://attacker',
                PIP_CERT: '/mnt/data/fake-ca',
                PIP_TARGET: '/tmp/outside',
                npm_config_https_proxy: 'http://attacker',
                npm_config_cafile: '/mnt/data/fake-ca',
                npm_config_prefix: '/tmp/outside',
                HTTP_PROXY: 'http://attacker',
                HTTPS_PROXY: 'http://attacker',
                SSL_CERT_FILE: '/mnt/data/fake-ca',
                SAFE_VALUE: 'kept',
            }),
        ).toEqual({ SAFE_VALUE: 'kept' });
    });

    test('returns only bounded top-level package facts and counters', async () => {
        const workspace = await fsp.mkdtemp(
            path.join(os.tmpdir(), 'package-summary-'),
        );
        const distInfo = path.join(
            workspace,
            '.optale-packages/python/fixture_pkg-1.2.3.dist-info',
        );
        await fsp.mkdir(distInfo, { recursive: true });
        await fsp.writeFile(
            path.join(distInfo, 'METADATA'),
            'Name: fixture-pkg\nVersion: 1.2.3\nHome-page: https://secret.example/path\n',
        );
        await fsp.writeFile(path.join(distInfo, 'REQUESTED'), '');

        const summary = await collectPackageSetupSummary(
            workspace,
            {
                requestCount: 4,
                responseBytes: 2048,
                policyDigest: 'D'.repeat(43),
            },
            1234,
            'success',
        );

        expect(summary).toEqual([
            {
                manager: 'pip',
                requestedSpec: 'fixture-pkg==1.2.3',
                installedVersion: '1.2.3',
                durationMs: 1234,
                outcome: 'success',
                gatewayRequestCount: 4,
                gatewayResponseBytes: 2048,
                policyDigest: 'D'.repeat(43),
            },
        ]);
        expect(JSON.stringify(summary)).not.toContain('secret.example');
    });

    test('ships native npm and Bun wrappers without a generic job-wide proxy', async () => {
        const wrapperRoot = path.resolve(__dirname, '../helpers/package-bin');
        const npm = await fsp.readFile(path.join(wrapperRoot, 'npm'), 'utf8');
        const bun = await fsp.readFile(path.join(wrapperRoot, 'bun'), 'utf8');
        const entrypoint = await fsp.readFile(
            path.resolve(__dirname, '../helpers/package-entrypoint'),
            'utf8',
        );
        expect(npm).toContain('npm_config_https_proxy');
        expect(npm).toContain('/mnt/data/.optale-packages/node');
        expect(npm).toContain('npm_config_save_exact');
        expect(bun).toContain('HTTPS_PROXY');
        expect(bun).toContain('NODE_EXTRA_CA_CERTS');
        expect(bun).toContain('--cafile');
        expect(bun).toContain('--exact');
        expect(bun).toContain('/mnt/data/.optale-packages/bun');
        expect(entrypoint).toContain('/run/codeapi/package-proxy-ready');
        expect(entrypoint).toContain('exec "$@"');
    });

    test('attaches the bounded setup summary to the run result', async () => {
        const workspace = await fsp.mkdtemp(
            path.join(os.tmpdir(), 'package-result-'),
        );
        const distInfo = path.join(
            workspace,
            '.optale-packages/python/result_pkg-2.0.0.dist-info',
        );
        await fsp.mkdir(distInfo, { recursive: true });
        await fsp.writeFile(
            path.join(distInfo, 'METADATA'),
            'Name: result-pkg\nVersion: 2.0.0\n',
        );
        await fsp.writeFile(path.join(distInfo, 'REQUESTED'), '');
        const result: NsJailResult = {
            stdout: '',
            stderr: '',
            output: '',
            code: 0,
            signal: null,
            memory: null,
            message: null,
            status: null,
            cpu_time: null,
            wall_time: 321,
            package_transport: {
                requestCount: 2,
                responseBytes: 512,
                policyDigest: 'R'.repeat(43),
            },
        };

        await attachPackageSetupSummary(result, workspace);
        expect(result.package_setup).toEqual([
            {
                manager: 'pip',
                requestedSpec: 'result-pkg==2.0.0',
                installedVersion: '2.0.0',
                durationMs: 321,
                outcome: 'success',
                gatewayRequestCount: 2,
                gatewayResponseBytes: 512,
                policyDigest: 'R'.repeat(43),
            },
        ]);
    });

    test('includes npm artifact integrity when the manager records it', async () => {
        const workspace = await fsp.mkdtemp(
            path.join(os.tmpdir(), 'package-digest-'),
        );
        const root = path.join(workspace, '.optale-packages/node');
        const installed = path.join(root, 'node_modules/fixture-npm');
        await fsp.mkdir(installed, { recursive: true });
        await fsp.writeFile(
            path.join(root, 'package.json'),
            JSON.stringify({
                dependencies: { 'fixture-npm': '1.0.0' },
            }),
        );
        await fsp.writeFile(
            path.join(installed, 'package.json'),
            JSON.stringify({
                name: 'fixture-npm',
                version: '1.0.0',
            }),
        );
        await fsp.writeFile(
            path.join(root, 'package-lock.json'),
            JSON.stringify({
                packages: {
                    'node_modules/fixture-npm': {
                        version: '1.0.0',
                        integrity: 'sha512-' + 'A'.repeat(86),
                    },
                },
            }),
        );
        const [summary] = await collectPackageSetupSummary(
            workspace,
            {
                requestCount: 2,
                responseBytes: 512,
                policyDigest: 'I'.repeat(43),
            },
            100,
            'success',
        );
        expect(summary).toMatchObject({
            manager: 'npm',
            requestedSpec: 'fixture-npm@1.0.0',
            installedVersion: '1.0.0',
            artifactDigest: 'sha512-' + 'A'.repeat(86),
        });
    });
});
