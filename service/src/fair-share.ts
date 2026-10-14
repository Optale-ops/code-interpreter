/**
 * Fair share of the code engine between companies (tenants).
 *
 * The engine is the only component that sees every tenant, so it decides who
 * runs. Nothing here is a fixed cap:
 *
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
 *   tenant is under its share; otherwise it is refused with the time the
 *   tenant's oldest run must end.
 * - Under-share runs get a better queue priority than over-share runs.
 *
 * State lives in Redis and changes only inside one Lua script per decision, so
 * every API instance sees the same picture. An admitted run holds an entry
 * scored by its deadline (admission + the per-run wall cap); entries are
 * released when the run ends or the client disconnects, and expire by
 * themselves at the deadline, so a crashed instance cannot leak capacity.
 */
import { createHash } from 'crypto';
import type { Response } from 'express';
import type * as t from './types';
import { env, jobCompletionWaitTimeoutMs } from './config';
import { getPrincipal } from './auth/principal';
import { getExecutionIdentity } from './execution-identity';
import logger from './logger';

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

/** Every run's ceiling: the longest the API waits for a job before failing it. */
export const RUN_WALL_CAP_MS = jobCompletionWaitTimeoutMs(
  env.JOB_TIMEOUT,
  env.LAMBDA_MICROVM_LAUNCH_TIMEOUT_MS,
  env.EGRESS_GATEWAY_REVOKE_TIMEOUT_MS,
);

const STATE_TTL_MS = RUN_WALL_CAP_MS + 10 * DEMAND_DECAY_MS;

/* Shared Lua helpers. `observe` prunes runs past their deadline and returns the
 * tenant's admitted-run count, its demand average decayed to `now`, and its
 * last known weight. The average integrates the count held since the last
 * update, so it rises while runs are admitted and decays once they end. */
const LUA_PRELUDE = `
local prefix = ARGV[1]
local now = tonumber(ARGV[2])
local tau = tonumber(ARGV[3])
local stateTtl = tonumber(ARGV[4])

local function inflightKey(t) return prefix .. 'inflight:' .. t end
local function demandKey(t) return prefix .. 'demand:' .. t end

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

/* ARGV: prefix, now, tau, stateTtl, tenant, slot, deadline, weight, capacity,
 * floor, force. Returns {admitted, underShare, share, count, retryAt}. */
const ADMIT_SCRIPT = `${LUA_PRELUDE}
local tenant = ARGV[5]
local slot = ARGV[6]
local deadline = tonumber(ARGV[7])
local weight = tonumber(ARGV[8])
local capacity = tonumber(ARGV[9])
local floor = tonumber(ARGV[10])
local force = ARGV[11] == '1'
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
  redis.call('ZADD', ikey, deadline, slot)
  redis.call('PEXPIRE', ikey, stateTtl)
  store(tenant, mine.avg, mine.count + 1, weight)
  return { 1, underShare and 1 or 0, share, mine.count + 1, 0 }
end

store(tenant, mine.avg, mine.count, weight)
local oldest = redis.call('ZRANGE', inflightKey(tenant), 0, 0, 'WITHSCORES')
local retryAt = tonumber(oldest[2]) or (now + 1000)
return { 0, 0, share, mine.count, retryAt }
`;

/* ARGV: prefix, now, tau, stateTtl, tenant, slot. Returns removed count. */
const RELEASE_SCRIPT = `${LUA_PRELUDE}
local tenant = ARGV[5]
local removed = redis.call('ZREM', inflightKey(tenant), ARGV[6])
local count, avg, w = observe(tenant)
store(tenant, avg, count, w)
return removed
`;

type FairShareRedis = {
  eval(script: string, numKeys: number, ...args: (string | number)[]): Promise<unknown>;
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
};

export type FairShareDecision = FairShareAdmission | FairShareRefusal;

export type AdmitRunInput = {
  tenantId: string;
  /** Unique per admitted run. */
  slotId: string;
  /** The tenant's code-capable Agents; at least 1. */
  weight: number;
  /** Continuations of an already admitted run: counted, never refused. */
  force?: boolean;
  /** Test seam; production uses the wall clock. */
  now?: number;
  capacity?: number;
};

function scriptArgs(now: number): (string | number)[] {
  return [FAIR_SHARE_KEY_PREFIX, now, DEMAND_DECAY_MS, STATE_TTL_MS];
}

export async function releaseRun(tenantId: string, slotId: string, now = Date.now()): Promise<void> {
  const redis = await getRedis();
  await redis.eval(RELEASE_SCRIPT, 0, ...scriptArgs(now), tenantId, slotId);
}

export async function admitRun(input: AdmitRunInput): Promise<FairShareDecision> {
  const now = input.now ?? Date.now();
  const capacity = input.capacity ?? env.CODE_RUN_CAPACITY;
  const weight = Math.max(1, Math.floor(input.weight));
  const redis = await getRedis();
  const reply = await redis.eval(
    ADMIT_SCRIPT,
    0,
    ...scriptArgs(now),
    input.tenantId,
    input.slotId,
    now + RUN_WALL_CAP_MS,
    weight,
    capacity,
    ACTIVE_DEMAND_FLOOR,
    input.force === true ? '1' : '0',
  ) as Array<number | string>;
  const [admitted, underShare, share, inFlight, retryAt] = reply.map(Number);
  if (admitted !== 1) {
    return { admitted: false, share, inFlight, retryAtMs: retryAt };
  }
  let releasing: Promise<void> | undefined;
  return {
    admitted: true,
    priority: underShare === 1 ? UNDER_SHARE_PRIORITY : OVER_SHARE_PRIORITY,
    underShare: underShare === 1,
    share,
    inFlight,
    release() {
      releasing ??= releaseRun(input.tenantId, input.slotId).catch((error: unknown) => {
        /* The entry still expires at its deadline. */
        logger.warn('Fair-share release failed; the slot expires at its deadline', { error });
      });
      return releasing;
    },
  };
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
  return {
    error: 'rate_limited',
    reason: 'tenant_share_exceeded',
    message: `The code engine is full and your company is using its share (${slots}; ${refusal.inFlight} of its runs are running or queued). A slot frees by ${retryAt.slice(11, 19)} UTC (in about ${retryAfterSeconds} s).`,
    retry_at: retryAt,
    retry_after_seconds: retryAfterSeconds,
    share: refusal.share,
    in_flight: refusal.inFlight,
  };
}

/**
 * Admits one code run for the request's tenant, or answers (429 rate_limited
 * with reason `tenant_share_exceeded`, or 503 when Redis cannot decide) and
 * returns null. The slot is released when the response is sent unless
 * `releaseOnClose` is false, in which case the caller releases it when the run
 * ends; routes also release when their run settles.
 */
export async function admitRequestRun(
  req: t.AuthenticatedRequest,
  res: Response,
  options: { slotId: string; force?: boolean; releaseOnClose?: boolean },
): Promise<FairShareAdmission | null> {
  const tenantId = getExecutionIdentity(req).storageNamespace;
  let decision: FairShareDecision;
  try {
    decision = await admitRun({
      tenantId,
      slotId: options.slotId,
      weight: getPrincipal(req)?.codeAgents ?? 1,
      force: options.force,
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
