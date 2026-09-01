import { describe, expect, test } from 'bun:test';

const invocation = (await import('../helpers/package-invocation.cjs')) as {
    sanitizeRequestedSpec(manager: 'pip' | 'npm' | 'bun', value: unknown): string | undefined;
    invocationRecord(
        manager: 'pip' | 'npm' | 'bun',
        start: number,
        end: number,
        status: number,
        argv: string[],
    ): {
        manager: 'pip' | 'npm' | 'bun';
        requestedSpecs: string[];
        durationMs: number;
        outcome: 'success' | 'failed';
    } | undefined;
};

describe('package invocation requested-spec sanitization', () => {
    test.each([
        ['npm', '@scope/pkg@^1'],
        ['bun', 'plain-pkg@~2.4'],
        ['pip', 'requests[security]>=2'],
        ['pip', 'urllib3!=2.2.0,<3'],
    ] as const)('preserves safe %s registry spec %s', (manager, spec) => {
        expect(invocation.sanitizeRequestedSpec(manager, spec)).toBe(spec);
    });

    test.each([
        ['pip', 'pkg @ https://user:secret@example.test/pkg.whl'],
        ['pip', 'git+https://user:secret@example.test/repo.git'],
        ['pip', 'file:../pkg'],
        ['pip', '../pkg'],
        ['pip', '/tmp/pkg.whl'],
        ['npm', 'pkg@https://user:secret@example.test/pkg.tgz'],
        ['npm', 'github:user/repo'],
        ['bun', './pkg.tgz'],
        ['bun', 'file:../pkg'],
    ] as const)('drops unsafe %s positional value without echoing it: %s', (manager, spec) => {
        expect(invocation.sanitizeRequestedSpec(manager, spec)).toBeUndefined();
    });

    test('pip wrapper capture skips option values and preserves safe top-level specs', () => {
        expect(
            invocation.invocationRecord('pip', 200, 225, 0, [
                'install',
                '--index-url',
                'https://user:secret@example.test/simple',
                'requests[security]>=2',
                'urllib3!=2.2.0,<3',
            ]),
        ).toEqual({
            manager: 'pip',
            requestedSpecs: ['requests[security]>=2', 'urllib3!=2.2.0,<3'],
            durationMs: 25,
            outcome: 'success',
        });
    });

    test('failed invocations retain only sanitized requested specs', () => {
        expect(
            invocation.invocationRecord('pip', 100, 117, 1, [
                'install',
                'requests[security]>=2',
                'pkg @ https://user:secret@example.test/pkg.whl',
                '../local.whl',
            ]),
        ).toEqual({
            manager: 'pip',
            requestedSpecs: ['requests[security]>=2'],
            durationMs: 17,
            outcome: 'failed',
        });
    });
});
