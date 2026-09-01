import { afterEach, describe, expect, test } from 'bun:test';
import path from 'path';
import { env } from './config';
import {
  validateApiHardenedConfig,
  validateEgressGatewayHardenedConfig,
  validateExecutionProfilePolicy,
  validateSandboxBackendPolicy,
  validateWorkerHardenedConfig,
} from './secure-startup';

const savedEnv = { ...process.env };
const saved = {
  hardened: env.HARDENED_SANDBOX_MODE,
  executionProfile: env.EXECUTION_PROFILE,
  executionProfileSource: env.EXECUTION_PROFILE_SOURCE,
  sandboxBackend: env.SANDBOX_BACKEND,
  ptcMode: env.PTC_MODE,
  runtimeSessionMode: env.RUNTIME_SESSION_MODE,
  lambdaImageArn: env.LAMBDA_MICROVM_IMAGE_ARN,
  lambdaImageVersion: env.LAMBDA_MICROVM_IMAGE_VERSION,
  lambdaEgressConnectors: env.LAMBDA_MICROVM_EGRESS_CONNECTOR_ARNS,
  lambdaPort: env.LAMBDA_MICROVM_PORT,
  lambdaMaxDuration: env.LAMBDA_MICROVM_MAX_DURATION_SECONDS,
  lambdaIdleSeconds: env.LAMBDA_MICROVM_IDLE_SECONDS,
  lambdaSuspendSeconds: env.LAMBDA_MICROVM_SUSPEND_SECONDS,
  lambdaTokenTtl: env.LAMBDA_MICROVM_AUTH_TOKEN_TTL_SECONDS,
  lambdaLaunchTimeout: env.LAMBDA_MICROVM_LAUNCH_TIMEOUT_MS,
  lambdaHealthTimeout: env.LAMBDA_MICROVM_HEALTH_TIMEOUT_MS,
  lambdaLaunchTps: env.LAMBDA_MICROVM_LAUNCH_TPS,
  lambdaTokenTps: env.LAMBDA_MICROVM_TOKEN_TPS,
  lambdaAllowShell: env.LAMBDA_MICROVM_ALLOW_SHELL,
  jobTimeout: env.JOB_TIMEOUT,
  lockWait: env.RUNTIME_SESSION_LOCK_WAIT_MS,
  checkpoints: env.SESSION_CHECKPOINTS,
  checkpointMaxBytes: env.CHECKPOINT_MAX_BYTES,
  checkpointTimeout: env.CHECKPOINT_TIMEOUT_MS,
  gatewayUrl: env.EGRESS_GATEWAY_URL,
  grantSecret: env.EGRESS_GRANT_SECRET,
  privateKey: env.EXECUTION_MANIFEST_PRIVATE_KEY,
  hmacSecret: env.EXECUTION_MANIFEST_SECRET,
  ledgerRequired: env.EGRESS_LEDGER_REQUIRED,
  fileServerUrl: env.EGRESS_GATEWAY_FILE_SERVER_URL,
  toolCallUrl: env.EGRESS_GATEWAY_TOOL_CALL_SERVER_URL,
  externalFetchPolicyFile: env.EXTERNAL_FETCH_POLICY_FILE,
};

function restore(): void {
  for (const key of Object.keys(process.env)) {
    if (!(key in savedEnv)) delete process.env[key];
  }
  Object.assign(process.env, savedEnv);
  env.HARDENED_SANDBOX_MODE = saved.hardened;
  env.EXECUTION_PROFILE = saved.executionProfile;
  env.EXECUTION_PROFILE_SOURCE = saved.executionProfileSource;
  env.SANDBOX_BACKEND = saved.sandboxBackend;
  env.PTC_MODE = saved.ptcMode;
  env.RUNTIME_SESSION_MODE = saved.runtimeSessionMode;
  env.LAMBDA_MICROVM_IMAGE_ARN = saved.lambdaImageArn;
  env.LAMBDA_MICROVM_IMAGE_VERSION = saved.lambdaImageVersion;
  env.LAMBDA_MICROVM_EGRESS_CONNECTOR_ARNS = saved.lambdaEgressConnectors;
  env.LAMBDA_MICROVM_PORT = saved.lambdaPort;
  env.LAMBDA_MICROVM_MAX_DURATION_SECONDS = saved.lambdaMaxDuration;
  env.LAMBDA_MICROVM_IDLE_SECONDS = saved.lambdaIdleSeconds;
  env.LAMBDA_MICROVM_SUSPEND_SECONDS = saved.lambdaSuspendSeconds;
  env.LAMBDA_MICROVM_AUTH_TOKEN_TTL_SECONDS = saved.lambdaTokenTtl;
  env.LAMBDA_MICROVM_LAUNCH_TIMEOUT_MS = saved.lambdaLaunchTimeout;
  env.LAMBDA_MICROVM_HEALTH_TIMEOUT_MS = saved.lambdaHealthTimeout;
  env.LAMBDA_MICROVM_LAUNCH_TPS = saved.lambdaLaunchTps;
  env.LAMBDA_MICROVM_TOKEN_TPS = saved.lambdaTokenTps;
  env.LAMBDA_MICROVM_ALLOW_SHELL = saved.lambdaAllowShell;
  env.JOB_TIMEOUT = saved.jobTimeout;
  env.RUNTIME_SESSION_LOCK_WAIT_MS = saved.lockWait;
  env.SESSION_CHECKPOINTS = saved.checkpoints;
  env.CHECKPOINT_MAX_BYTES = saved.checkpointMaxBytes;
  env.CHECKPOINT_TIMEOUT_MS = saved.checkpointTimeout;
  env.EGRESS_GATEWAY_URL = saved.gatewayUrl;
  env.EGRESS_GRANT_SECRET = saved.grantSecret;
  env.EXECUTION_MANIFEST_PRIVATE_KEY = saved.privateKey;
  env.EXECUTION_MANIFEST_SECRET = saved.hmacSecret;
  env.EGRESS_LEDGER_REQUIRED = saved.ledgerRequired;
  env.EGRESS_GATEWAY_FILE_SERVER_URL = saved.fileServerUrl;
  env.EGRESS_GATEWAY_TOOL_CALL_SERVER_URL = saved.toolCallUrl;
  env.EXTERNAL_FETCH_POLICY_FILE = saved.externalFetchPolicyFile;
}

afterEach(restore);

async function runFreshGateway(
  overrides: Record<string, string>,
): Promise<{ status: number; stderr: string }> {
  const child = Bun.spawn(
    [process.execPath, '-e', "await import('./src/egress-gateway.ts')"],
    {
      cwd: path.resolve(__dirname, '..'),
      env: {
        ...process.env,
        CODEAPI_EGRESS_GATEWAY_AUTOSTART: 'false',
        CODEAPI_HARDENED_SANDBOX_MODE: 'true',
        CODEAPI_EGRESS_LEDGER_REQUIRED: 'true',
        CODEAPI_EGRESS_GRANT_SECRET: 'strong-egress-grant-secret-32-bytes',
        CODEAPI_INTERNAL_SERVICE_TOKEN: 'strong-internal-service-token-32-bytes',
        EGRESS_GATEWAY_FILE_SERVER_URL: 'http://file-server:3000',
        EGRESS_GATEWAY_TOOL_CALL_SERVER_URL: 'http://tool-call-server:3033',
        CODEAPI_EXTERNAL_FETCH_POLICY_FILE: path.resolve(__dirname, '../config/external-fetch-policy.json'),
        CODEAPI_SYNTHETIC_ACCESS_TOKEN: '',
        REDIS_HOST: 'redis',
        REDIS_PASSWORD: 'test-only-redis-password',
        ...overrides,
      },
      stdout: 'pipe',
      stderr: 'pipe',
    },
  );
  const [status, stderr] = await Promise.all([
    child.exited,
    new Response(child.stderr).text(),
  ]);
  return { status, stderr };
}

describe('execution profile policy', () => {
  test('accepts the AWS-free default profile', () => {
    env.EXECUTION_PROFILE = 'default';
    env.EXECUTION_PROFILE_SOURCE = 'explicit';
    env.SANDBOX_BACKEND = 'http';
    env.RUNTIME_SESSION_MODE = 'stateless';
    expect(() => validateExecutionProfilePolicy()).not.toThrow();
  });

  test('accepts affinity and strict stateful profiles', () => {
    env.EXECUTION_PROFILE = 'stateful';
    env.EXECUTION_PROFILE_SOURCE = 'explicit';
    env.SANDBOX_BACKEND = 'lambda-microvm';
    env.RUNTIME_SESSION_MODE = 'affinity';
    expect(() => validateExecutionProfilePolicy()).not.toThrow();
    env.RUNTIME_SESSION_MODE = 'strict';
    expect(() => validateExecutionProfilePolicy()).not.toThrow();
  });

  test('does not require worker-only backend config on API-only pods', () => {
    env.EXECUTION_PROFILE = 'stateful';
    env.EXECUTION_PROFILE_SOURCE = 'explicit';
    env.SANDBOX_BACKEND = 'http';
    env.RUNTIME_SESSION_MODE = 'affinity';
    expect(() => validateExecutionProfilePolicy({ requireBackendMatch: false })).not.toThrow();
  });

  test('rejects a default profile backed by AWS or stateful sessions', () => {
    env.EXECUTION_PROFILE = 'default';
    env.EXECUTION_PROFILE_SOURCE = 'explicit';
    env.SANDBOX_BACKEND = 'lambda-microvm';
    env.RUNTIME_SESSION_MODE = 'stateless';
    expect(() => validateExecutionProfilePolicy()).toThrow(
      'CODEAPI_EXECUTION_PROFILE=default requires',
    );

    env.SANDBOX_BACKEND = 'http';
    env.RUNTIME_SESSION_MODE = 'affinity';
    expect(() => validateExecutionProfilePolicy()).toThrow(
      'CODEAPI_EXECUTION_PROFILE=default requires',
    );
  });

  test('preserves a pre-profile Lambda/stateless deployment when inferred', () => {
    env.EXECUTION_PROFILE = 'default';
    env.EXECUTION_PROFILE_SOURCE = 'inferred';
    env.SANDBOX_BACKEND = 'lambda-microvm';
    env.RUNTIME_SESSION_MODE = 'stateless';
    expect(() => validateExecutionProfilePolicy()).not.toThrow();
  });

  test('rejects a stateful profile without Lambda affinity', () => {
    env.EXECUTION_PROFILE = 'stateful';
    env.EXECUTION_PROFILE_SOURCE = 'explicit';
    env.SANDBOX_BACKEND = 'http';
    env.RUNTIME_SESSION_MODE = 'affinity';
    expect(() => validateExecutionProfilePolicy()).toThrow(
      'CODEAPI_EXECUTION_PROFILE=stateful requires',
    );

    env.SANDBOX_BACKEND = 'lambda-microvm';
    env.RUNTIME_SESSION_MODE = 'stateless';
    expect(() => validateExecutionProfilePolicy()).toThrow(
      'CODEAPI_EXECUTION_PROFILE=stateful requires',
    );
  });
});

describe('hardened CodeAPI startup config', () => {
  test('rejects grant secrets in API and worker processes', () => {
    env.HARDENED_SANDBOX_MODE = true;
    env.EGRESS_GATEWAY_URL = 'http://egress-gateway:3190';
    env.EXECUTION_MANIFEST_PRIVATE_KEY = 'private-key';
    process.env.CODEAPI_INTERNAL_SERVICE_TOKEN = 'strong-internal-service-token-32-bytes';
    process.env.CODEAPI_EGRESS_GRANT_SECRET = 'must-not-be-here';

    expect(() => validateApiHardenedConfig()).toThrow('CODEAPI_EGRESS_GRANT_SECRET');
    expect(() => validateWorkerHardenedConfig()).toThrow('CODEAPI_EGRESS_GRANT_SECRET');
  });

  test('rejects legacy HMAC signing in hardened worker mode', () => {
    env.HARDENED_SANDBOX_MODE = true;
    env.EGRESS_GATEWAY_URL = 'http://egress-gateway:3190';
    env.EXECUTION_MANIFEST_PRIVATE_KEY = 'private-key';
    process.env.CODEAPI_EXECUTION_MANIFEST_SECRET = 'legacy-secret';
    process.env.CODEAPI_INTERNAL_SERVICE_TOKEN = 'strong-internal-service-token-32-bytes';

    expect(() => validateWorkerHardenedConfig()).toThrow('CODEAPI_EXECUTION_MANIFEST_SECRET');
  });

  test('keeps synthetic auth token out of worker and egress processes', () => {
    env.HARDENED_SANDBOX_MODE = true;
    env.EGRESS_GATEWAY_URL = 'http://egress-gateway:3190';
    env.EXECUTION_MANIFEST_PRIVATE_KEY = 'private-key';
    env.EGRESS_GRANT_SECRET = 'strong-egress-grant-secret-32-bytes';
    env.EGRESS_LEDGER_REQUIRED = true;
    env.EGRESS_GATEWAY_FILE_SERVER_URL = 'http://file-server:3000';
    env.EGRESS_GATEWAY_TOOL_CALL_SERVER_URL = 'http://tool-call-server:3033';
    env.EXTERNAL_FETCH_POLICY_FILE = '/run/codeapi/external-fetch-policy.json';
    process.env.REDIS_HOST = 'redis';
    process.env.CODEAPI_INTERNAL_SERVICE_TOKEN = 'strong-internal-service-token-32-bytes';
    process.env.CODEAPI_SYNTHETIC_ACCESS_TOKEN = 'synthetic-token-must-stay-on-api';

    expect(() => validateWorkerHardenedConfig()).toThrow('CODEAPI_SYNTHETIC_ACCESS_TOKEN');
    expect(() => validateEgressGatewayHardenedConfig()).toThrow('CODEAPI_SYNTHETIC_ACCESS_TOKEN');
  });

  test('requires gateway URL, internal auth, and worker manifest private key', () => {
    env.HARDENED_SANDBOX_MODE = true;
    env.EGRESS_GATEWAY_URL = '';
    env.EXECUTION_MANIFEST_PRIVATE_KEY = 'private-key';
    process.env.CODEAPI_INTERNAL_SERVICE_TOKEN = 'strong-internal-service-token-32-bytes';

    expect(() => validateApiHardenedConfig()).toThrow('EGRESS_GATEWAY_URL');
    expect(() => validateWorkerHardenedConfig()).toThrow('EGRESS_GATEWAY_URL');

    env.EGRESS_GATEWAY_URL = 'http://egress-gateway:3190';
    delete process.env.CODEAPI_INTERNAL_SERVICE_TOKEN;
    expect(() => validateApiHardenedConfig()).toThrow('CODEAPI_INTERNAL_SERVICE_TOKEN');
    expect(() => validateWorkerHardenedConfig()).toThrow('CODEAPI_INTERNAL_SERVICE_TOKEN');

    process.env.CODEAPI_INTERNAL_SERVICE_TOKEN = 'strong-internal-service-token-32-bytes';
    env.EXECUTION_MANIFEST_PRIVATE_KEY = '';
    expect(() => validateWorkerHardenedConfig()).toThrow('CODEAPI_EXECUTION_MANIFEST_PRIVATE_KEY');
  });

  test('refuses a fresh hardened gateway process when the ledger is disabled', async () => {
    const result = await runFreshGateway({ CODEAPI_EGRESS_LEDGER_REQUIRED: 'false' });
    expect(result.status).not.toBe(0);
    expect(result.stderr).toContain('CODEAPI_EGRESS_LEDGER_REQUIRED must be true');
  });

  test('refuses a weak internal token in a fresh hardened gateway process', async () => {
    const result = await runFreshGateway({ CODEAPI_INTERNAL_SERVICE_TOKEN: 'x' });
    expect(result.status).not.toBe(0);
    expect(result.stderr).toContain('CODEAPI_INTERNAL_SERVICE_TOKEN must be at least 32 bytes');
  });

  test.each([
    [
      'grant secret',
      { CODEAPI_EGRESS_GRANT_SECRET: 'localdev-egress-grant-secret-change-me-32b' },
      'CODEAPI_EGRESS_GRANT_SECRET must not use a shipped development value',
    ],
    [
      'internal token',
      { CODEAPI_INTERNAL_SERVICE_TOKEN: 'localdev-internal-service-token' },
      'CODEAPI_INTERNAL_SERVICE_TOKEN must not use a shipped development value',
    ],
    [
      'padded grant secret',
      { CODEAPI_EGRESS_GRANT_SECRET: ' localdev-egress-grant-secret-change-me-32b ' },
      'CODEAPI_EGRESS_GRANT_SECRET must not use a shipped development value',
    ],
    [
      'padded internal token',
      { CODEAPI_INTERNAL_SERVICE_TOKEN: ' localdev-internal-service-token ' },
      'CODEAPI_INTERNAL_SERVICE_TOKEN must not use a shipped development value',
    ],
    [
      'Helm grant secret',
      { CODEAPI_EGRESS_GRANT_SECRET: 'changeme-egress-grant-secret-32-bytes-minimum' },
      'CODEAPI_EGRESS_GRANT_SECRET must not use a shipped development value',
    ],
    [
      'Helm internal token',
      { CODEAPI_INTERNAL_SERVICE_TOKEN: 'changeme-in-production' },
      'CODEAPI_INTERNAL_SERVICE_TOKEN must not use a shipped development value',
    ],
    [
      'padded Helm grant secret',
      { CODEAPI_EGRESS_GRANT_SECRET: ' changeme-egress-grant-secret-32-bytes-minimum ' },
      'CODEAPI_EGRESS_GRANT_SECRET must not use a shipped development value',
    ],
    [
      'padded Helm internal token',
      { CODEAPI_INTERNAL_SERVICE_TOKEN: ' changeme-in-production ' },
      'CODEAPI_INTERNAL_SERVICE_TOKEN must not use a shipped development value',
    ],
  ])('refuses the shipped local %s in a fresh hardened gateway process', async (_label, overrides, message) => {
    const result = await runFreshGateway(overrides);
    expect(result.status).not.toBe(0);
    expect(result.stderr).toContain(message);
  });

  test('requires strong gateway secret, Redis ledger credentials, and upstream URLs', () => {
    env.HARDENED_SANDBOX_MODE = true;
    env.EGRESS_GRANT_SECRET = 'strong-egress-grant-secret-32-bytes';
    env.EGRESS_LEDGER_REQUIRED = true;
    process.env.CODEAPI_INTERNAL_SERVICE_TOKEN = 'strong-internal-service-token-32-bytes';
    process.env.REDIS_HOST = 'redis';
    process.env.REDIS_PASSWORD = 'test-only-redis-password';

    env.EGRESS_GATEWAY_FILE_SERVER_URL = '';
    env.EGRESS_GATEWAY_TOOL_CALL_SERVER_URL = 'http://tool-call-server:3033';
    expect(() => validateEgressGatewayHardenedConfig()).toThrow('EGRESS_GATEWAY_FILE_SERVER_URL');

    env.EGRESS_GATEWAY_FILE_SERVER_URL = 'http://file-server:3000';
    env.EGRESS_GATEWAY_TOOL_CALL_SERVER_URL = '';
    expect(() => validateEgressGatewayHardenedConfig()).toThrow('EGRESS_GATEWAY_TOOL_CALL_SERVER_URL');
    env.EGRESS_GATEWAY_TOOL_CALL_SERVER_URL = 'http://tool-call-server:3033';
    env.EXTERNAL_FETCH_POLICY_FILE = '';
    expect(() => validateEgressGatewayHardenedConfig()).toThrow('CODEAPI_EXTERNAL_FETCH_POLICY_FILE');

    env.EXTERNAL_FETCH_POLICY_FILE = '/run/codeapi/external-fetch-policy.json';

    env.EGRESS_GATEWAY_TOOL_CALL_SERVER_URL = 'http://tool-call-server:3033';
    delete process.env.REDIS_HOST;
    expect(() => validateEgressGatewayHardenedConfig()).toThrow('REDIS_HOST');

    process.env.REDIS_HOST = 'redis';
    delete process.env.REDIS_PASSWORD;
    expect(() => validateEgressGatewayHardenedConfig()).toThrow(
      'REDIS_PASSWORD is required in CODEAPI_HARDENED_SANDBOX_MODE',
    );

    process.env.REDIS_PASSWORD = '   ';
    expect(() => validateEgressGatewayHardenedConfig()).toThrow(
      'REDIS_PASSWORD is required in CODEAPI_HARDENED_SANDBOX_MODE',
    );

    process.env.REDIS_PASSWORD = 'test-only-redis-password';
    expect(() => validateEgressGatewayHardenedConfig()).not.toThrow();

    env.EGRESS_GRANT_SECRET = 'short';
    expect(() => validateEgressGatewayHardenedConfig()).toThrow('at least 32 bytes');

  });
});

describe('sandbox backend policy', () => {
  function configureValidLambda(): void {
    env.SANDBOX_BACKEND = 'lambda-microvm';
    env.HARDENED_SANDBOX_MODE = false;
    env.PTC_MODE = 'replay';
    env.RUNTIME_SESSION_MODE = 'stateless';
    env.LAMBDA_MICROVM_IMAGE_ARN = 'arn:aws:lambda:us-east-2:1:microvm-image:codeapi';
    env.LAMBDA_MICROVM_IMAGE_VERSION = '3';
    env.LAMBDA_MICROVM_EGRESS_CONNECTOR_ARNS = undefined;
    env.LAMBDA_MICROVM_PORT = 8080;
    env.LAMBDA_MICROVM_MAX_DURATION_SECONDS = 28_800;
    env.LAMBDA_MICROVM_IDLE_SECONDS = 1_800;
    env.LAMBDA_MICROVM_SUSPEND_SECONDS = 1_800;
    env.LAMBDA_MICROVM_AUTH_TOKEN_TTL_SECONDS = 300;
    env.LAMBDA_MICROVM_LAUNCH_TIMEOUT_MS = 60_000;
    env.LAMBDA_MICROVM_HEALTH_TIMEOUT_MS = 5_000;
    env.LAMBDA_MICROVM_LAUNCH_TPS = 4;
    env.LAMBDA_MICROVM_TOKEN_TPS = 8;
    env.LAMBDA_MICROVM_ALLOW_SHELL = false;
    env.JOB_TIMEOUT = 300_000;
    env.RUNTIME_SESSION_LOCK_WAIT_MS = 15_000;
    env.SESSION_CHECKPOINTS = true;
    env.CHECKPOINT_MAX_BYTES = 512 * 1024 * 1024;
    env.CHECKPOINT_TIMEOUT_MS = 60_000;
    /* Object storage for the (default-on) session checkpoints. */
    process.env.MINIO_ENDPOINT = 'minio';
    process.env.MINIO_ACCESS_KEY = 'access';
    process.env.MINIO_SECRET_KEY = 'secret';
    process.env.CODEAPI_CHECKPOINT_BUCKET = 'codeapi-checkpoints';
  }

  test('accepts the default http backend', () => {
    env.SANDBOX_BACKEND = 'http';
    env.RUNTIME_SESSION_MODE = 'stateless';
    expect(() => validateSandboxBackendPolicy()).not.toThrow();
  });

  test('accepts a fully configured stateless lambda backend', () => {
    configureValidLambda();
    expect(() => validateSandboxBackendPolicy()).not.toThrow();
  });

  test('stateful runtime session modes require the lambda backend', () => {
    env.SANDBOX_BACKEND = 'http';
    env.RUNTIME_SESSION_MODE = 'affinity';
    expect(() => validateSandboxBackendPolicy()).toThrow('requires the lambda-microvm backend');
    env.RUNTIME_SESSION_MODE = 'strict';
    expect(() => validateSandboxBackendPolicy()).toThrow('requires the lambda-microvm backend');
  });

  test('rejects blocking PTC on the lambda backend', () => {
    configureValidLambda();
    env.PTC_MODE = 'blocking';
    expect(() => validateSandboxBackendPolicy()).toThrow('PTC replay is the only supported PTC mode');
  });

  test('requires the image ARN', () => {
    configureValidLambda();
    env.LAMBDA_MICROVM_IMAGE_ARN = '';
    expect(() => validateSandboxBackendPolicy()).toThrow('LAMBDA_MICROVM_IMAGE_ARN is required');
  });

  test('accepts affinity and strict session modes on the lambda backend', () => {
    configureValidLambda();
    env.RUNTIME_SESSION_MODE = 'affinity';
    expect(() => validateSandboxBackendPolicy()).not.toThrow();
    env.RUNTIME_SESSION_MODE = 'strict';
    expect(() => validateSandboxBackendPolicy()).not.toThrow();
  });

  test('accepts the production checkpoint budget and rejects an impossible one', () => {
    configureValidLambda();
    env.RUNTIME_SESSION_MODE = 'affinity';
    /* Production defaults reserve 60s for the whole token mint, 60s for each
     * archive transfer, 5s for each object metadata operation, and 5s for
     * each of the six registry operations: 220s total. */
    expect(() => validateSandboxBackendPolicy()).not.toThrow();

    env.JOB_TIMEOUT = 220_000;
    expect(() => validateSandboxBackendPolicy()).toThrow(
      'JOB_TIMEOUT must exceed the full session checkpoint reserve (220000ms)',
    );
  });

  test('stateful session modes require a pinned image version', () => {
    configureValidLambda();
    env.RUNTIME_SESSION_MODE = 'affinity';
    env.LAMBDA_MICROVM_IMAGE_VERSION = undefined;
    expect(() => validateSandboxBackendPolicy()).toThrow(
      'LAMBDA_MICROVM_IMAGE_VERSION must be pinned',
    );
  });

  test('rejects session checkpoints without object storage configured', () => {
    configureValidLambda();
    env.RUNTIME_SESSION_MODE = 'affinity';
    delete process.env.MINIO_ENDPOINT;
    expect(() => validateSandboxBackendPolicy()).toThrow('object storage is not configured');
    /* stateless never touches the store, so it stays valid without MinIO */
    env.RUNTIME_SESSION_MODE = 'stateless';
    expect(() => validateSandboxBackendPolicy()).not.toThrow();
  });

  test('accepts IAM-role checkpoint credentials and rejects a partial static pair', () => {
    configureValidLambda();
    env.RUNTIME_SESSION_MODE = 'affinity';
    delete process.env.MINIO_ACCESS_KEY;
    delete process.env.MINIO_SECRET_KEY;
    expect(() => validateSandboxBackendPolicy()).not.toThrow();

    process.env.MINIO_ACCESS_KEY = 'incomplete';
    expect(() => validateSandboxBackendPolicy()).toThrow('MINIO_SECRET_KEY');
  });

  test('hardened mode requires an egress connector', () => {
    configureValidLambda();
    env.HARDENED_SANDBOX_MODE = true;
    expect(() => validateSandboxBackendPolicy()).toThrow('LAMBDA_MICROVM_EGRESS_CONNECTOR_ARNS is required');
    env.LAMBDA_MICROVM_EGRESS_CONNECTOR_ARNS = ['arn:aws:lambda:us-east-2:1:network-connector:vpc-egress'];
    expect(() => validateSandboxBackendPolicy()).not.toThrow();
  });

  test('hardened mode rejects public INTERNET_EGRESS, including mixed connector lists', () => {
    configureValidLambda();
    env.HARDENED_SANDBOX_MODE = true;
    const publicEgress =
      'arn:aws:lambda:us-east-2:aws:network-connector:aws-network-connector:INTERNET_EGRESS';
    const vpcEgress = 'arn:aws:lambda:us-east-2:1:network-connector:vpc-egress';

    env.LAMBDA_MICROVM_EGRESS_CONNECTOR_ARNS = [publicEgress];
    expect(() => validateSandboxBackendPolicy()).toThrow('INTERNET_EGRESS');

    env.LAMBDA_MICROVM_EGRESS_CONNECTOR_ARNS = [vpcEgress, publicEgress];
    expect(() => validateSandboxBackendPolicy()).toThrow('INTERNET_EGRESS');

    env.LAMBDA_MICROVM_EGRESS_CONNECTOR_ARNS = [vpcEgress];
    expect(() => validateSandboxBackendPolicy()).not.toThrow();
  });

  test('rejects invalid Lambda numeric config and preserves suspend=0', () => {
    configureValidLambda();
    env.LAMBDA_MICROVM_IDLE_SECONDS = 59;
    expect(() => validateSandboxBackendPolicy()).toThrow(
      'LAMBDA_MICROVM_IDLE_SECONDS must be a whole number between 60 and 28800',
    );

    configureValidLambda();
    env.LAMBDA_MICROVM_MAX_DURATION_SECONDS = 28_801;
    expect(() => validateSandboxBackendPolicy()).toThrow(
      'LAMBDA_MICROVM_MAX_DURATION_SECONDS must be a whole number between 1 and 28800',
    );

    configureValidLambda();
    env.LAMBDA_MICROVM_SUSPEND_SECONDS = 0;
    expect(() => validateSandboxBackendPolicy()).not.toThrow();
  });

  test('rejects unbounded or invalid session deadline and checkpoint controls', () => {
    configureValidLambda();
    env.RUNTIME_SESSION_LOCK_WAIT_MS = Number.POSITIVE_INFINITY;
    expect(() => validateSandboxBackendPolicy()).toThrow(
      'CODEAPI_RUNTIME_SESSION_LOCK_WAIT_MS',
    );

    configureValidLambda();
    env.CHECKPOINT_MAX_BYTES = Number.POSITIVE_INFINITY;
    expect(() => validateSandboxBackendPolicy()).toThrow(
      'CODEAPI_CHECKPOINT_MAX_BYTES',
    );

    configureValidLambda();
    env.CHECKPOINT_TIMEOUT_MS = 0;
    expect(() => validateSandboxBackendPolicy()).toThrow(
      'CODEAPI_CHECKPOINT_TIMEOUT_MS',
    );

    configureValidLambda();
    env.JOB_TIMEOUT = Number.NaN;
    expect(() => validateSandboxBackendPolicy()).toThrow('JOB_TIMEOUT');
  });

  test('caps ingress token TTL and blocks shell ingress in hardened mode', () => {
    configureValidLambda();
    env.LAMBDA_MICROVM_AUTH_TOKEN_TTL_SECONDS = 901;
    expect(() => validateSandboxBackendPolicy()).toThrow('must be a whole number between 1 and 900');

    configureValidLambda();
    env.LAMBDA_MICROVM_ALLOW_SHELL = true;
    expect(() => validateSandboxBackendPolicy()).not.toThrow();
    env.HARDENED_SANDBOX_MODE = true;
    env.LAMBDA_MICROVM_EGRESS_CONNECTOR_ARNS = ['arn:aws:lambda:us-east-2:1:network-connector:vpc-egress'];
    expect(() => validateSandboxBackendPolicy()).toThrow('LAMBDA_MICROVM_ALLOW_SHELL');
  });
});
