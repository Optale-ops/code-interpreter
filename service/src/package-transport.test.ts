import { describe, expect, test } from 'bun:test';
import {
    packageTransportRequestHeaders,
    validatePackageTransportMethod,
    validatePackageTransportResponseHeaders,
} from './external-fetch';
import { ExternalFetchError } from './external-fetch-errors';

describe('package transport request contract', () => {
    test('permits GET and HEAD only', () => {
        expect(validatePackageTransportMethod('GET')).toBe('GET');
        expect(validatePackageTransportMethod('head')).toBe('HEAD');
        for (const method of [
            'POST',
            'PUT',
            'PATCH',
            'DELETE',
            'CONNECT',
            'OPTIONS',
        ]) {
            expect(() => validatePackageTransportMethod(method)).toThrow(
                ExternalFetchError,
            );
        }
    });

    test('strips credentials, hop-by-hop headers, bodies, and caller routing controls', () => {
        expect(
            packageTransportRequestHeaders({
                accept: 'application/json',
                'user-agent': 'npm/10',
                authorization: 'Bearer secret',
                cookie: 'session=secret',
                'proxy-authorization': 'Basic secret',
                connection: 'x-remove',
                'x-remove': 'secret',
                host: 'attacker.example',
                'content-length': '123',
                'transfer-encoding': 'chunked',
                range: 'bytes=0-10',
            }),
        ).toEqual({
            accept: 'application/json',
            'user-agent': 'npm/10',
            range: 'bytes=0-10',
            'accept-encoding': 'identity',
            connection: 'close',
        });
    });

    test('accepts bounded identity responses and rejects compressed transfer', () => {
        expect(
            validatePackageTransportResponseHeaders(
                {
                    'content-type': 'application/octet-stream',
                    'content-length': '1024',
                    'content-encoding': 'identity',
                },
                2048,
            ),
        ).toEqual({ declaredBytes: 1024 });

        expect(() =>
            validatePackageTransportResponseHeaders(
                {
                    'content-encoding': 'gzip',
                },
                2048,
            ),
        ).toThrow(ExternalFetchError);
    });
});
