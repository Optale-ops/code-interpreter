import { describe, expect, it } from 'bun:test';
import { createPayload } from './payload';
import type { AuthenticatedRequest } from './types';

function executeRequest(env_vars?: unknown): AuthenticatedRequest {
  return {
    body: {
      lang: 'python',
      code: 'print("ok")',
      files: [],
      env_vars,
    },
  } as unknown as AuthenticatedRequest;
}

function queuedPayload(env_vars?: unknown) {
  return createPayload({
    req: executeRequest(env_vars),
    session_id: 'session-env-vars',
  });
}

describe('createPayload env_vars', () => {
  it('includes accepted environment variable names in the queued payload', () => {
    const payload = queuedPayload({ FEATURE_FLAG: 'enabled', SERVICE_BASE: 'https://example.invalid' });

    expect(payload.env_vars).toBeDefined();
    expect(Object.keys(payload.env_vars ?? {}).sort()).toEqual(['FEATURE_FLAG', 'SERVICE_BASE']);
  });

  it('uses the runner sanitizer for key and value shape', () => {
    const payload = queuedPayload({
      ACCEPTED_NAME: 'present',
      'invalid-name': 'discarded',
      INVALID_VALUE: 42,
    });

    expect(Object.keys(payload.env_vars ?? {})).toEqual(['ACCEPTED_NAME']);
  });

  it('rejects more than 256 environment entries', () => {
    const entries = Object.fromEntries(Array.from({ length: 257 }, (_, index) => [`ENV_${index}`, 'x']));

    expect(() => queuedPayload(entries)).toThrow('env_vars exceeds maximum count of 256');
  });

  it('rejects environment data above the runner byte cap', () => {
    expect(() => queuedPayload({ OVERSIZED: 'x'.repeat(1_000_000) }))
      .toThrow('env_vars exceeds maximum total size of 1000000 bytes');
  });
});
