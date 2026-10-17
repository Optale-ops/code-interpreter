import { describe, expect, test } from 'bun:test';
import {
  checkExecutionProfileExpectation,
  queueNameForExecutionProfile,
  resolveExecutionProfile,
  resolveExecutionProfileSource,
  validateQueuedExecutionProfile,
} from './execution-profile';

describe('execution profile resolution', () => {
  test('preserves the HTTP/stateless default when unset', () => {
    expect(resolveExecutionProfile(undefined, 'stateless')).toBe('default');
  });

  test('recognizes an existing stateful deployment when unset', () => {
    expect(resolveExecutionProfile(undefined, 'affinity')).toBe('stateful');
    expect(resolveExecutionProfile(undefined, 'strict')).toBe('stateful');
  });

  test('lets API-only pods infer stateful from session mode without worker config', () => {
    expect(resolveExecutionProfile(undefined, 'affinity')).toBe('stateful');
  });

  test('accepts only the two public execution profiles', () => {
    expect(resolveExecutionProfile('default', 'stateless')).toBe('default');
    expect(resolveExecutionProfile('stateful', 'affinity')).toBe('stateful');
    expect(() => resolveExecutionProfile('lambda', 'affinity')).toThrow(
      'CODEAPI_EXECUTION_PROFILE must be one of: default, stateful',
    );
    expect(resolveExecutionProfile('', 'stateless')).toBe('default');
    expect(resolveExecutionProfile('   ', 'affinity')).toBe('stateful');
    expect(resolveExecutionProfileSource('')).toBe('inferred');
    expect(resolveExecutionProfileSource('stateful')).toBe('explicit');
  });
});

describe('execution profile queue isolation', () => {
  test('runs the default profile on the default run queue', () => {
    expect(queueNameForExecutionProfile('default', 'explicit')).toBe('code-run-queue');
  });

  test('keeps inferred stateful deployments on the default run queue during binary rollout', () => {
    expect(queueNameForExecutionProfile('stateful', 'inferred')).toBe('code-run-queue');
  });

  test('uses a separate run queue only for an explicit stateful deployment', () => {
    expect(queueNameForExecutionProfile('stateful', 'explicit')).toBe('stateful-code-run-queue');
  });
});

describe('execution profile request assertion', () => {
  test('allows callers that omit the assertion for backwards compatibility', () => {
    expect(checkExecutionProfileExpectation(undefined, 'default')).toEqual({ ok: true });
  });

  test('allows a matching expected profile', () => {
    expect(checkExecutionProfileExpectation('stateful', 'stateful')).toEqual({ ok: true });
  });

  test('returns a typed conflict before a mismatched request can be routed', () => {
    expect(checkExecutionProfileExpectation('stateful', 'default')).toEqual({
      ok: false,
      status: 409,
      body: {
        error: 'execution_profile_mismatch',
        message: 'Expected the stateful execution profile, but reached default',
        expected_profile: 'stateful',
        actual_profile: 'default',
      },
    });
  });

  test('rejects invalid profile names instead of treating them as mismatches', () => {
    expect(checkExecutionProfileExpectation('aws', 'default')).toMatchObject({
      ok: false,
      status: 400,
      body: {
        error: 'invalid_execution_profile',
        expected_profile: 'aws',
        actual_profile: 'default',
      },
    });
  });
});

describe('queued execution profile validation', () => {
  test('accepts matching and legacy jobs', () => {
    expect(() => validateQueuedExecutionProfile('stateful', 'stateful')).not.toThrow();
    expect(() => validateQueuedExecutionProfile(undefined, 'default')).not.toThrow();
  });

  test('rejects invalid and cross-profile jobs', () => {
    expect(() => validateQueuedExecutionProfile('invalid', 'default')).toThrow(
      'Queued job has invalid execution profile',
    );
    expect(() => validateQueuedExecutionProfile('stateful', 'default')).toThrow(
      'Queued job targets the stateful execution profile, but worker serves default',
    );
  });
});
