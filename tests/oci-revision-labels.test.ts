import { describe, expect, test } from 'bun:test';
import fsp from 'node:fs/promises';
import path from 'node:path';

const root = path.resolve(__dirname, '..');

describe('candidate image source provenance', () => {
    test.each([
        'service/Dockerfile',
        'service/Dockerfile.egress-gateway',
        'service/Dockerfile.tool-call-server',
        'api/Dockerfile',
        'launcher/Dockerfile',
    ])(
        '%s carries the OCI source revision label',
        async file => {
            const source = await fsp.readFile(path.join(root, file), 'utf8');
            expect(source).toContain('ARG SOURCE_REVISION');
            expect(source).toContain('org.opencontainers.image.revision');
        },
    );

    test('builds the per-job package proxy for the production Node runtime', async () => {
        const packageJson = JSON.parse(
            await fsp.readFile(path.join(root, 'api/package.json'), 'utf8'),
        );
        expect(packageJson.scripts.build).toContain('package-proxy.ts');
        const dockerfile = await fsp.readFile(
            path.join(root, 'api/Dockerfile'),
            'utf8',
        );
        expect(dockerfile).toContain('/sandbox_api/nsenter');
        expect(dockerfile).toContain('/sandbox_api/unshare');
        expect(dockerfile).toContain('    iproute2');
        expect(dockerfile).toContain('package-entrypoint');
        expect(dockerfile).toContain('package-bin');
        const boundaryCompose = await fsp.readFile(
            path.join(root, 'docker-compose.external-fetch-test.yml'),
            'utf8',
        );
        expect(boundaryCompose).toContain('- NET_ADMIN');
    });

    test.each(['production', 'api', 'worker', 'egress-gateway'])(
        'service image stage %s carries the source revision label',
        async stage => {
            const source = await fsp.readFile(path.join(root, 'service/Dockerfile'), 'utf8');
            const section = source.split(new RegExp(`FROM [^\n]+ AS ${stage}\n`))[1]?.split('\nFROM ')[0] ?? '';
            expect(section).toContain('ARG SOURCE_REVISION');
            expect(section).toContain('LABEL org.opencontainers.image.revision=$SOURCE_REVISION');
        },
    );
});
