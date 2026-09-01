import { describe, expect, it } from 'bun:test';
import { sanitizeEnvVars } from './api/v2';

describe('runner env_vars sanitizer', () => {
  it('rejects more than 256 environment entries', () => {
    const entries = Object.fromEntries(Array.from({ length: 257 }, (_, index) => [`ENV_${index}`, 'x']));

    expect(() => sanitizeEnvVars(entries)).toThrow('env_vars exceeds maximum count of 256');
  });
});
