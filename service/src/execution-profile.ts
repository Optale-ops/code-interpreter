export const EXECUTION_PROFILES = ['default', 'stateful'] as const;

export type ExecutionProfile = typeof EXECUTION_PROFILES[number];
export type ExecutionProfileSource = 'explicit' | 'inferred';

export const EXPECTED_EXECUTION_PROFILE_HEADER = 'X-CodeAPI-Expected-Profile';
export const EXECUTION_PROFILE_HEADER = 'X-CodeAPI-Execution-Profile';

export function resolveExecutionProfile(
  raw: string | undefined,
  runtimeSessionMode: 'stateless' | 'affinity' | 'strict',
): ExecutionProfile {
  const configuredChoice = raw?.trim();
  if (configuredChoice) {
    if (EXECUTION_PROFILES.includes(configuredChoice as ExecutionProfile)) {
      return configuredChoice as ExecutionProfile;
    }
    throw new Error(
      `CODEAPI_EXECUTION_PROFILE must be one of: ${EXECUTION_PROFILES.join(', ')}`,
    );
  }

  /* Preserve the two supported pre-profile deployments during rollout. The
   * common stateless stack remains `default`; a stateful API-only pod can
   * infer `stateful` from its session mode even though worker-only backend
   * credentials/config are intentionally absent. Worker startup separately
   * verifies that this profile is backed by Lambda. */
  return runtimeSessionMode !== 'stateless'
    ? 'stateful'
    : 'default';
}

export function resolveExecutionProfileSource(
  raw: string | undefined,
): ExecutionProfileSource {
  return raw?.trim() ? 'explicit' : 'inferred';
}

const DEFAULT_QUEUE_NAME = 'code-run-queue';

const EXPLICIT_PROFILE_QUEUE_NAMES: Record<ExecutionProfile, string> = {
  default: DEFAULT_QUEUE_NAME,
  stateful: 'stateful-code-run-queue',
};

/** The one BullMQ queue every code run of the profile goes through, whatever
 * its language. */
export function queueNameForExecutionProfile(
  profile: ExecutionProfile,
  source: ExecutionProfileSource,
): string {
  /* A pre-profile affinity/strict deployment used the default queue. Keep
   * inferred profiles on that name so API and worker Deployments can roll
   * or roll back independently without temporarily losing their consumers.
   * Queue isolation is an explicit cutover: operators bring up the stateful
   * stack with CODEAPI_EXECUTION_PROFILE=stateful on both sides, then switch
   * callers to its endpoint. */
  return source === 'explicit'
    ? EXPLICIT_PROFILE_QUEUE_NAMES[profile]
    : DEFAULT_QUEUE_NAME;
}

export type ExecutionProfileExpectation =
  | { ok: true }
  | {
    ok: false;
    status: 400 | 409;
    body: {
      error: 'invalid_execution_profile' | 'execution_profile_mismatch';
      message: string;
      expected_profile?: string;
      actual_profile: ExecutionProfile;
    };
  };

export function checkExecutionProfileExpectation(
  rawExpectedProfile: string | undefined,
  actualProfile: ExecutionProfile,
): ExecutionProfileExpectation {
  if (rawExpectedProfile == null) return { ok: true };

  if (!EXECUTION_PROFILES.includes(rawExpectedProfile as ExecutionProfile)) {
    return {
      ok: false,
      status: 400,
      body: {
        error: 'invalid_execution_profile',
        message: `Invalid execution profile: ${rawExpectedProfile}`,
        expected_profile: rawExpectedProfile,
        actual_profile: actualProfile,
      },
    };
  }

  if (rawExpectedProfile !== actualProfile) {
    return {
      ok: false,
      status: 409,
      body: {
        error: 'execution_profile_mismatch',
        message: `Expected the ${rawExpectedProfile} execution profile, but reached ${actualProfile}`,
        expected_profile: rawExpectedProfile,
        actual_profile: actualProfile,
      },
    };
  }

  return { ok: true };
}

/** Reject producer/consumer profile drift before a worker invokes a sandbox.
 * Missing profile is accepted only for jobs queued by pre-profile binaries. */
export function validateQueuedExecutionProfile(
  jobProfile: unknown,
  workerProfile: ExecutionProfile,
): void {
  if (jobProfile == null) return;
  if (!EXECUTION_PROFILES.includes(jobProfile as ExecutionProfile)) {
    throw new Error(`Queued job has invalid execution profile: ${String(jobProfile)}`);
  }
  if (jobProfile !== workerProfile) {
    throw new Error(
      `Queued job targets the ${jobProfile} execution profile, but worker serves ${workerProfile}`,
    );
  }
}
