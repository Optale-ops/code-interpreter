import { describe, expect, test } from 'bun:test';
import { buildArgs, renderJobConfig } from './nsjail';

function valueAfter(args: string[], flag: string): string | undefined {
    const index = args.indexOf(flag);
    return index >= 0 ? args[index + 1] : undefined;
}

describe('package proxy jail boundary', () => {
    test('enables IPv4 loopback only for the per-job proxy and mounts public trust only', () => {
        const rendered = renderJobConfig(
            'clone_newnet: true\niface_no_lo: true\n',
            '/tmp/job-workspace',
            '/tmp/job-package-ca.pem',
        );
        expect(rendered).toContain('clone_newnet: true');
        expect(rendered).toContain('iface_no_lo: false');
        expect(rendered).not.toContain('iface_no_lo: true');
        expect(rendered).toContain('dst: "/run/codeapi/package-ca.pem"');
        expect(rendered).not.toContain('ca-key');
    });

    test('allows IPv4 sockets only in package jobs while retaining IPv6 and control-domain denials', () => {
        const base = {
            logPath: '/tmp/nsjail-test.log',
            pkgdir: '/pkgs/bash/5.2.0',
            timeout: 1000,
            memoryLimit: -1,
            envVars: {},
            command: ['/bin/bash', '/pkgs/bash/5.2.0/run', 'main.sh'],
            identity: { slot: 0, uid: 65534, gid: 65534, perJobUid: false },
        };
        const ordinary = valueAfter(buildArgs(base), '--seccomp_string') ?? '';
        const packaged =
            valueAfter(
                buildArgs({
                    ...base,
                    externalFetchGrantFile: '/tmp/job-grant',
                    packageProxyCaFile: '/tmp/job-ca.pem',
                    packageProxyReadyFile: '/tmp/job-ready',
                }),
                '--seccomp_string',
            ) ?? '';

        expect(ordinary).toContain('domain == AF_INET || domain == AF_INET6');
        expect(packaged).not.toContain(
            'domain == AF_INET || domain == AF_INET6',
        );
        expect(packaged).toContain('domain == AF_INET6');
        expect(packaged).toContain('domain == AF_NETLINK');
        expect(buildArgs(base)).not.toContain('--disable_clone_newnet');
        expect(
            buildArgs({
                ...base,
                externalFetchGrantFile: '/tmp/job-grant',
                packageProxyCaFile: '/tmp/job-ca.pem',
                packageProxyReadyFile: '/tmp/job-ready',
            }),
        ).toContain('--disable_clone_newnet');
    });

    test('binds the CA and readiness sentinel without exposing the CA key', () => {
        const args = buildArgs({
            logPath: '/tmp/nsjail-test.log',
            pkgdir: '/pkgs/bash/5.2.0',
            timeout: 1000,
            memoryLimit: -1,
            envVars: {},
            command: ['/bin/bash', '/pkgs/bash/5.2.0/run', 'main.sh'],
            identity: { slot: 0, uid: 65534, gid: 65534, perJobUid: false },
            externalFetchGrantFile: '/tmp/job-grant',
            packageProxyCaFile: '/tmp/job-ca.pem',
            packageProxyReadyFile: '/tmp/job-ready',
        });
        expect(args.join('\n')).not.toContain(
            '/tmp/job-ca.pem:/run/codeapi/package-ca.pem',
        );
        expect(args.join('\n')).toContain(
            '/tmp/job-ready:/run/codeapi/package-proxy-ready',
        );
        expect(args.join('\n')).not.toContain('ca-key');
        expect(args.join('\n')).toContain(
            '/usr/local/lib/sandbox-fetch/package-entrypoint',
        );
    });
});
