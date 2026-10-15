/**
 * Fair share of the code engine between companies (tenants).
 *
 * The engine is the only component that sees every tenant, so it decides who
 * runs. Nothing here is a fixed cap:
 *
 * - Every code run, of any language, comes from one pool: the run queue that
 *   all workers drain. Its capacity is CODE_RUN_CAPACITY (runs one worker and
 *   its sandbox take at once) times the worker count (CODE_WORKER_REPLICAS).
 * - With spare capacity every run is admitted, even past the capacity (the
 *   job waits in the queue). Shares bind only when other tenants have current
 *   or predicted demand.
 * - Each tenant's demand is a decaying average of its admitted runs (running
 *   plus queued) over about the last minute. A tenant that was just busy keeps
 *   a predicted slice for the next moments instead of losing it the instant
 *   its runs finish; an idle tenant reserves nothing.
 * - Capacity is divided by weight (the tenant's code-capable Agents, from the
 *   signed `code_agents` claim) among tenants with current or predicted demand.
 *   Spare capacity is what is left after every other tenant's predicted,
 *   not-yet-used slice. A run is admitted while there is spare capacity or its
 *   tenant is under its share; otherwise it is refused with the time a slot is
 *   likely to free: the admission of the run whose end brings the tenant back
 *   under its share (its (count - share + 1)-th oldest) plus the 90th
 *   percentile of recent run durations, never later than that run's deadline.
 * - Under-share runs get a better queue priority than over-share runs.
 *
 * State lives in Redis and changes only inside one Lua script per decision, so
 * every API instance sees the same picture. An admitted run holds an entry
 * named `<INSTANCE_ID>:<slot>` and scored by its deadline (admission + the
 * per-run wall cap); entries are released when the run ends or the client
 * disconnects, expire by themselves at the deadline, and an API instance drops
 * its own leftovers when it starts.
 */
import { createHash } from 'crypto';
import type { Response } from 'express';
import type * as t from './types';
import { env, jobCompletionWaitTimeoutMs } from './config';
import { queueNameForExecutionProfile } from './execution-profile';
import { getPrincipal } from './auth/principal';
import { getExecutionIdentity } from './execution-identity';
import logger from './logger';
import { sleep } from './utils';

/** One hash tag keeps every fair-share key in one Redis Cluster slot. */
export const FAIR_SHARE_KEY_PREFIX = '{codeapi-fair-share}:';
/** Time constant of the demand average: demand left by one run decays below
 * the activity floor after about three time constants (one minute). */
export const DEMAND_DECAY_MS = 20_000;
/** Decayed demand below this counts as idle. */
export const ACTIVE_DEMAND_FLOOR = 0.05;
/** BullMQ priorities: lower runs first. Every fair-share job carries one, so
 * no job bypasses the ordering through the unprioritized wait list. */
export const UNDER_SHARE_PRIORITY = 1;
export const OVER_SHARE_PRIORITY = 2;
/** Recent run durations kept for the retry estimate. */
export const DURATION_SAMPLES = 100;
/** The soonest a refused run is told to come back. */
const MIN_RETRY_MS = 1_000;
/** How long a starting API waits for restarted workers to publish a changed
 * capacity before it refuses to start. */
const WORKER_CAPACITY_WAIT_MS = 120_000;

/** Every run's ceiling: the longest the API waits for a job before failing it. */
export const RUN_WALL_CAP_MS = jobCompletionWaitTimeoutMs(
  env.JOB_TIMEOUT,
  env.LAMBDA_MICROVM_LAUNCH_TIMEOUT_MS,
  env.EGRESS_GATEWAY_REVOKE_TIMEOUT_MS,
);

const STATE_TTL_MS = RUN_WALL_CAP_MS + 10 * DEMAND_DECAY_MS;

/** Runs the pool takes at once: what every worker runs at once together. The
 * BullMQ limiter allows the same count per JOB_WINDOW, so for runs longer than
 * the window concurrency is what binds. */
export function poolCapacity(): number {
  return env.CODE_RUN_CAPACITY * env.CODE_WORKER_REPLICAS;
}

/** Keys of the pool, under the run queue's BullMQ name so execution profiles
 * sharing a Redis never mix. */
function poolPrefix(): string {
  return `${FAIR_SHARE_KEY_PREFIX}${queueNameForExecutionProfile(env.EXECUTION_PROFILE, env.EXECUTION_PROFILE_SOURCE)}:`;
}

/** The slot's entry, tagged with this API instance so a restart can drop it. */
function slotMember(slotId: string): string {
  return `${env.INSTANCE_ID}:${slotId}`;
}

/* Shared Lua helpers. `observe` prunes runs past their deadline and returns the
 * tenant's admitted-run count, its demand average decayed to `now`, and its
 * last known weight. The average integrates the count held since the last
 * update, so it rises while runs are admitted and decays once they end. */
const LUA_PRELUDE = `
local prefix = ARGV[1]
local now = tonumber(ARGV[2])
local tau = tonumber(ARGV[3])
local stateTtl = tonumber(ARGV[4])
local wallCap = tonumber(ARGV[5])

local function inflightKey(t) return prefix .. 'inflight:' .. t end
local function demandKey(t) return prefix .. 'demand:' .. t end
local durationsKey = prefix .. 'durations'

local function observe(t)
  local ikey = inflightKey(t)
  redis.call('ZREMRANGEBYSCORE', ikey, '-inf', now)
  local count = tonumber(redis.call('ZCARD', ikey))
  local h = redis.call('HMGET', demandKey(t), 'avg', 'at', 'n', 'w')
  local avg = tonumber(h[1]) or 0
  local at = tonumber(h[2]) or now
  local held = tonumber(h[3]) or 0
  local w = tonumber(h[4]) or 1
  local dt = now - at
  if dt < 0 then dt = 0 end
  avg = held + (avg - held) * math.exp(-dt / tau)
  return count, avg, w
end

local function store(t, avg, count, w)
  local hkey = demandKey(t)
  redis.call('HSET', hkey, 'avg', tostring(avg), 'at', tostring(now), 'n', tostring(count), 'w', tostring(w))
  redis.call('PEXPIRE', hkey, stateTtl)
end
`;

/* ARGV: prefix, now, tau, stateTtl, wallCap, tenant, slot, weight, capacity,
 * floor, force, minRetry. Returns {admitted, underShare, share, count, retryAt,
 * estimated}. */
const ADMIT_SCRIPT = `${LUA_PRELUDE}
local tenant = ARGV[6]
local slot = ARGV[7]
local weight = tonumber(ARGV[8])
local capacity = tonumber(ARGV[9])
local floor = tonumber(ARGV[10])
local force = ARGV[11] == '1'
local minRetry = tonumber(ARGV[12])
local tenantsKey = prefix .. 'tenants'

local function predicted(count, avg)
  if avg < floor then return count end
  local p = math.ceil(avg - 0.000001)
  if p < count then return count end
  return p
end

local mine = { count = 0, avg = 0 }
local others = {}
local total = 0
local totalWeight = weight
for _, t in ipairs(redis.call('SMEMBERS', tenantsKey)) do
  local count, avg, w = observe(t)
  total = total + count
  if t == tenant then
    mine.count = count
    mine.avg = avg
  elseif count > 0 or avg >= floor then
    store(t, avg, count, w)
    totalWeight = totalWeight + w
    table.insert(others, { count = count, avg = avg, w = w })
  else
    redis.call('SREM', tenantsKey, t)
    redis.call('DEL', demandKey(t), inflightKey(t))
  end
end

local function shareOf(w)
  local s = math.floor(capacity * w / totalWeight)
  if s < 1 then return 1 end
  return s
end

local share = shareOf(weight)
local underShare = mine.count < share
local reserved = 0
for _, o in ipairs(others) do
  local slice = math.min(shareOf(o.w), predicted(o.count, o.avg)) - o.count
  if slice > 0 then reserved = reserved + slice end
end
local spare = capacity - total - reserved > 0

redis.call('SADD', tenantsKey, tenant)
if force or #others == 0 or spare or underShare then
  local ikey = inflightKey(tenant)
  redis.call('ZADD', ikey, now + wallCap, slot)
  redis.call('PEXPIRE', ikey, stateTtl)
  store(tenant, mine.avg, mine.count + 1, weight)
  return { 1, underShare and 1 or 0, share, mine.count + 1, 0, 0 }
end

store(tenant, mine.avg, mine.count, weight)
-- The tenant is back under its share once count - share + 1 of its runs end;
-- runs end roughly in admission order, so the estimate follows that run.
local nth = mine.count - share
if nth < 0 then nth = 0 end
local entry = redis.call('ZRANGE', inflightKey(tenant), nth, nth, 'WITHSCORES')
local deadline = tonumber(entry[2])
if not deadline then
  return { 0, 0, share, mine.count, now + minRetry, 1 }
end
local samples = redis.call('LRANGE', durationsKey, 0, -1)
if #samples == 0 then
  return { 0, 0, share, mine.count, deadline, 0 }
end
local durations = {}
for i, d in ipairs(samples) do durations[i] = tonumber(d) end
table.sort(durations)
local p90 = durations[math.ceil(#durations * 0.9)]
local retryAt = deadline - wallCap + p90
if retryAt < now + minRetry then retryAt = now + minRetry end
if retryAt > deadline then retryAt = deadline end
return { 0, 0, share, mine.count, retryAt, 1 }
`;

/* ARGV: prefix, now, tau, stateTtl, wallCap, tenant, slot, samples. Records the
 * run's duration (admission to release) unless samples is 0, and returns the
 * removed count. */
const RELEASE_SCRIPT = `${LUA_PRELUDE}
local tenant = ARGV[6]
local slot = ARGV[7]
local samples = tonumber(ARGV[8])
local ikey = inflightKey(tenant)
local deadline = tonumber(redis.call('ZSCORE', ikey, slot))
local removed = redis.call('ZREM', ikey, slot)
if removed == 1 and deadline and samples > 0 then
  local duration = now - (deadline - wallCap)
  if duration >= 0 then
    redis.call('LPUSH', durationsKey, duration)
    redis.call('LTRIM', durationsKey, 0, samples - 1)
  end
end
local count, avg, w = observe(tenant)
store(tenant, avg, count, w)
return removed
`;

/* ARGV: prefix, instance prefix. Removes every entry an earlier run of this API
 * instance left behind and returns how many. */
const DROP_INSTANCE_SCRIPT = `
local prefix = ARGV[1]
local mine = ARGV[2]
local dropped = 0
for _, t in ipairs(redis.call('SMEMBERS', prefix .. 'tenants')) do
  local ikey = prefix .. 'inflight:' .. t
  for _, member in ipairs(redis.call('ZRANGE', ikey, 0, -1)) do
    if string.sub(member, 1, #mine) == mine then
      dropped = dropped + redis.call('ZREM', ikey, member)
    end
  end
end
return dropped
`;

type FairShareRedis = {
  eval(script: string, numKeys: number, ...args: (string | number)[]): Promise<unknown>;
  get(key: string): Promise<string | null>;
  set(key: string, value: string): Promise<unknown>;
};

let redisOverride: FairShareRedis | undefined;

async function getRedis(): Promise<FairShareRedis> {
  if (redisOverride) return redisOverride;
  /* Lazy like middleware/limits.ts: importing ./queue opens the shared Redis
   * connection and BullMQ queues, which unit tests of this module must not do. */
  const { connection } = await import('./queue');
  return connection as unknown as FairShareRedis;
}

export function setFairShareRedisForTests(client?: FairShareRedis): void {
  redisOverride = client;
}

export type FairShareAdmission = {
  admitted: true;
  priority: number;
  underShare: boolean;
  share: number;
  inFlight: number;
  /** Idempotent: frees the run's slot; every call returns the same promise. */
  release(): Promise<void>;
};

export type FairShareRefusal = {
  admitted: false;
  share: number;
  inFlight: number;
  retryAtMs: number;
  /** False when no run durations are known yet and `retryAtMs` is the
   * deadline of the run that frees the slot, the latest it can free. */
  estimated: boolean;
};

export type FairShareDecision = FairShareAdmission | FairShareRefusal;

export type AdmitRunInput = {
  tenantId: string;
  /** Unique per admitted run. */
  slotId: string;
  /** The tenant's Agents that ran code recently; at least 1. */
  weight: number;
  /** Continuations of an already admitted run: counted, never refused. */
  force?: boolean;
  /** False when the run's admission-to-release time is not a run duration
   * (a blocking programmatic job also waits on tool calls): kept off the
   * samples the retry estimate uses. */
  sampleDuration?: boolean;
  /** Test seams; production uses the wall clock and the pool's capacity. */
  now?: number;
  capacity?: number;
};

function scriptArgs(now: number): (string | number)[] {
  return [poolPrefix(), now, DEMAND_DECAY_MS, STATE_TTL_MS, RUN_WALL_CAP_MS];
}

export async function releaseRun(
  tenantId: string,
  slotId: string,
  now = Date.now(),
  sampleDuration = true,
): Promise<void> {
  const redis = await getRedis();
  await redis.eval(
    RELEASE_SCRIPT,
    0,
    ...scriptArgs(now),
    tenantId,
    slotMember(slotId),
    sampleDuration ? DURATION_SAMPLES : 0,
  );
}

export async function admitRun(input: AdmitRunInput): Promise<FairShareDecision> {
  const now = input.now ?? Date.now();
  const capacity = input.capacity ?? poolCapacity();
  const weight = Math.max(1, Math.floor(input.weight));
  const redis = await getRedis();
  const reply = await redis.eval(
    ADMIT_SCRIPT,
    0,
    ...scriptArgs(now),
    input.tenantId,
    slotMember(input.slotId),
    weight,
    capacity,
    ACTIVE_DEMAND_FLOOR,
    input.force === true ? '1' : '0',
    MIN_RETRY_MS,
  ) as Array<number | string>;
  const [admitted, underShare, share, inFlight, retryAt, estimated] = reply.map(Number);
  if (admitted !== 1) {
    return { admitted: false, share, inFlight, retryAtMs: retryAt, estimated: estimated === 1 };
  }
  let releasing: Promise<void> | undefined;
  return {
    admitted: true,
    priority: underShare === 1 ? UNDER_SHARE_PRIORITY : OVER_SHARE_PRIORITY,
    underShare: underShare === 1,
    share,
    inFlight,
    release() {
      releasing ??= releaseRun(input.tenantId, input.slotId, Date.now(), input.sampleDuration !== false).catch((error: unknown) => {
        /* The entry still expires at its deadline. */
        logger.warn('Fair-share release failed; the slot expires at its deadline', { error });
      });
      return releasing;
    },
  };
}

/**
 * API startup: drops the entries an earlier run of this instance left behind
 * (a crash or restart mid-run), so they stop counting against their tenants
 * before their deadline. Only effective when INSTANCE_ID is stable across
 * restarts and unique per API instance. A dropped entry whose job is still
 * running lets fair share admit past the pool for a moment; the extra runs
 * wait in the queue, since no worker runs more than CODE_RUN_CAPACITY at once.
 */
export async function dropInstanceLeftovers(): Promise<number> {
  const redis = await getRedis();
  const dropped = Number(await redis.eval(DROP_INSTANCE_SCRIPT, 0, poolPrefix(), slotMember('')));
  if (dropped > 0) {
    logger.info(`[${env.INSTANCE_ID}] Dropped ${dropped} fair-share slot(s) left by this instance's previous run`);
  }
  return dropped;
}

/* What one worker runs at once, published by each worker at boot and checked
 * by the API, which divides the pool it makes up. */
function workerCapacityKey(): string {
  return `${poolPrefix()}worker-capacity`;
}

export async function publishWorkerCapacity(): Promise<void> {
  const redis = await getRedis();
  await redis.set(workerCapacityKey(), String(env.CODE_RUN_CAPACITY));
}

/**
 * API startup: refuses to start when the workers run a different
 * CODE_RUN_CAPACITY than this API divides between companies. A config change
 * recreates the API and the workers together and the API may come up first,
 * still seeing what the old workers published, so a mismatch is re-read until
 * `waitMs` passes before it is refused. No worker has published yet on a first
 * boot; that is logged, not refused.
 */
export async function assertWorkerCapacityAgrees(
  { waitMs = WORKER_CAPACITY_WAIT_MS, pollMs = 2_000 }: { waitMs?: number; pollMs?: number } = {},
): Promise<void> {
  const redis = await getRedis();
  const mine = String(env.CODE_RUN_CAPACITY);
  const giveUpAt = Date.now() + waitMs;
  let published = await redis.get(workerCapacityKey());
  if (published == null) {
    logger.warn(`[${env.INSTANCE_ID}] No worker has published its CODE_RUN_CAPACITY yet; fair share assumes ${mine}`);
    return;
  }
  if (published !== mine) {
    logger.warn(`[${env.INSTANCE_ID}] The workers run CODE_RUN_CAPACITY=${published}, this API ${mine}; waiting up to ${waitMs / 1000} s for restarted workers`);
  }
  while (published !== mine && Date.now() < giveUpAt) {
    await sleep(pollMs);
    published = await redis.get(workerCapacityKey());
  }
  if (published !== mine) {
    throw new Error(
      `Fair share: the workers run CODE_RUN_CAPACITY=${published} but this API is configured with ${mine}. Set CODE_RUN_CAPACITY to the same value on the API and the workers.`,
    );
  }
}

/**
 * The 429 body. `error: 'rate_limited'` with `retry_after_seconds` is the shape
 * the Console's agents client already turns into "retry after N seconds";
 * `reason` names the fair-share refusal for every other reader.
 */
export type FairShareRefusalBody = {
  error: 'rate_limited';
  reason: 'tenant_share_exceeded';
  message: string;
  retry_at: string;
  retry_after_seconds: number;
  share: number;
  in_flight: number;
};

export function fairShareRefusalBody(refusal: FairShareRefusal, now = Date.now()): FairShareRefusalBody {
  const retryAfterSeconds = Math.max(1, Math.ceil((refusal.retryAtMs - now) / 1000));
  const retryAt = new Date(Math.max(refusal.retryAtMs, now)).toISOString();
  const slots = refusal.share === 1 ? '1 slot' : `${refusal.share} slots`;
  const when = refusal.estimated
    ? `A slot is likely to free around ${retryAt.slice(11, 19)} UTC (in about ${retryAfterSeconds} s).`
    : `A slot frees by ${retryAt.slice(11, 19)} UTC at the latest (in about ${retryAfterSeconds} s).`;
  return {
    error: 'rate_limited',
    reason: 'tenant_share_exceeded',
    message: `The code engine is full and your company is using its share (${slots}; ${refusal.inFlight} of its runs are running or queued). ${when}`,
    retry_at: retryAt,
    retry_after_seconds: retryAfterSeconds,
    share: refusal.share,
    in_flight: refusal.inFlight,
  };
}

/**
 * Admits one code run from the pool for the request's tenant, or answers (429
 * rate_limited with reason `tenant_share_exceeded`, or 503 when Redis cannot
 * decide) and returns null. The slot is released when the response is sent
 * unless `releaseOnClose` is false, in which case the caller releases it when
 * the run ends; routes also release when their run settles.
 */
export async function admitRequestRun(
  req: t.AuthenticatedRequest,
  res: Response,
  options: {
    slotId: string;
    force?: boolean;
    releaseOnClose?: boolean;
    sampleDuration?: boolean;
  },
): Promise<FairShareAdmission | null> {
  const tenantId = getExecutionIdentity(req).storageNamespace;
  let decision: FairShareDecision;
  try {
    decision = await admitRun({
      tenantId,
      slotId: options.slotId,
      weight: getPrincipal(req)?.codeAgents ?? 1,
      force: options.force,
      sampleDuration: options.sampleDuration,
    });
  } catch (error) {
    logger.error('Fair-share admission failed', { error });
    res.status(503).json({ error: 'Code engine admission unavailable' });
    return null;
  }
  if (!decision.admitted) {
    const body = fairShareRefusalBody(decision);
    logger.warn('Code run refused: tenant at its fair share', {
      tenantHash: createHash('sha256').update(tenantId).digest('hex').slice(0, 12),
      share: decision.share,
      inFlight: decision.inFlight,
      retryAfterSeconds: body.retry_after_seconds,
      estimated: decision.estimated,
    });
    res.setHeader('Retry-After', String(body.retry_after_seconds));
    res.status(429).json(body);
    return null;
  }
  if (options.releaseOnClose !== false) {
    /* `finish` covers a completed response, `close` a client that left (Node).
     * Bun, the API's runtime, reports neither for a pending response whose
     * client left; the run still occupies the engine until it ends and the
     * handler answers, which then releases it. The deadline is the backstop. */
    const release = (): void => {
      void decision.release();
    };
    res.once('finish', release);
    res.once('close', release);
  }
  return decision;
}
