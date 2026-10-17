import { afterEach, beforeEach, describe, expect, test } from 'bun:test';
import express from 'express';
import { once } from 'events';
import type { Server } from 'http';
import type { AddressInfo } from 'net';
import RedisMock from 'ioredis-mock';
import { applyPrincipal } from './auth/principal';
import type { AuthenticatedRequest } from './types';
import { env } from './config';
import { queueNameForExecutionProfile } from './execution-profile';
import {
  DEMAND_DECAY_MS,
  FAIR_SHARE_KEY_PREFIX,
  OVER_SHARE_PRIORITY,
  RUN_WALL_CAP_MS,
  UNDER_SHARE_PRIORITY,
  admitRequestRun,
  admitRun,
  assertWorkerCapacityAgrees,
  dropInstanceLeftovers,
  poolCapacity,
  publishWorkerCapacity,
  releaseRun,
  setFairShareRedisForTests,
  type FairShareDecision,
} from './fair-share';

const CAPACITY = 4;
const T0 = 1_800_000_000_000;

/* One client for the file; every test starts from an empty keyspace. */
const redis = new RedisMock();
let slotCounter = 0;

const saved = {
  capacity: env.CODE_RUN_CAPACITY,
  replicas: env.CODE_WORKER_REPLICAS,
  instance: env.INSTANCE_ID,
};

beforeEach(async () => {
  await redis.flushall();
  setFairShareRedisForTests(redis);
  env.CODE_RUN_CAPACITY = CAPACITY;
  env.CODE_WORKER_REPLICAS = 1;
  env.INSTANCE_ID = 'api-1';
  slotCounter = 0;
});

afterEach(() => {
  setFairShareRedisForTests();
  env.CODE_RUN_CAPACITY = saved.capacity;
  env.CODE_WORKER_REPLICAS = saved.replicas;
  env.INSTANCE_ID = saved.instance;
});

function admit(tenantId: string, weight: number, now: number, slotId = `slot-${++slotCounter}`): Promise<FairShareDecision> {
  return admitRun({ tenantId, weight, now, slotId });
}

async function admitMany(tenantId: string, weight: number, now: number, count: number): Promise<FairShareDecision[]> {
  const decisions: FairShareDecision[] = [];
  for (let i = 0; i < count; i++) decisions.push(await admit(tenantId, weight, now));
  return decisions;
}

function inflightKey(tenantId: string): string {
  const queueName = queueNameForExecutionProfile(env.EXECUTION_PROFILE, env.EXECUTION_PROFILE_SOURCE);
  return `${FAIR_SHARE_KEY_PREFIX}${queueName}:inflight:${tenantId}`;
}

function inFlight(tenantId: string): Promise<number> {
  return redis.zcard(inflightKey(tenantId));
}

describe('fair-share admission', () => {
  test('an idle engine admits every run, far past the capacity and any former cap', async () => {
    const decisions = await admitMany('labA', 3, T0, 12);

    expect(decisions.every(d => d.admitted)).toBe(true);
    expect(await inFlight('labA')).toBe(12);
    /* Runs inside the tenant's share outrank the rest in the queue. */
    expect(decisions.map(d => d.admitted && d.priority)).toEqual([
      ...Array(CAPACITY).fill(UNDER_SHARE_PRIORITY),
      ...Array(12 - CAPACITY).fill(OVER_SHARE_PRIORITY),
    ]);
  });

  test('under contention, weights 3:1 split the capacity 3:1 and the over-share run is refused with retry_at', async () => {
    const b1 = await admit('labB', 1, T0);
    expect(b1.admitted).toBe(true);

    const a = await admitMany('labA', 3, T0 + 1_000, 4);
    expect(a.slice(0, 3).every(d => d.admitted)).toBe(true);
    /* No run has finished yet, so no duration is known: retry_at is the
     * ceiling, when labA's oldest run must end. */
    expect(a[3]).toEqual({
      admitted: false,
      share: 3,
      inFlight: 3,
      retryAtMs: T0 + 1_000 + RUN_WALL_CAP_MS,
      estimated: false,
    });

    const b2 = await admit('labB', 1, T0 + 2_000);
    expect(b2).toEqual({
      admitted: false,
      share: 1,
      inFlight: 1,
      retryAtMs: T0 + RUN_WALL_CAP_MS,
      estimated: false,
    });
  });

  test('retry_at is the freeing run\'s admission plus the p90 of recent run durations, within [now + 1 s, deadline]', async () => {
    /* Ten earlier runs took 1..10 s (p90 = 9 s). */
    for (let i = 1; i <= 10; i++) {
      await admit('labC', 1, T0, `c-${i}`);
      await releaseRun('labC', `c-${i}`, T0 + i * 1_000);
    }
    /* Long after labC went quiet, labB and labA fill the capacity of 4 (share 2 each). */
    const start = T0 + 10_000 + 10 * DEMAND_DECAY_MS;
    await admit('labB', 1, start);
    expect((await admitMany('labA', 1, start, 3)).every(d => d.admitted)).toBe(true);

    const refused = await admit('labA', 1, start + 2_000);
    expect(refused).toMatchObject({ admitted: false, estimated: true, retryAtMs: start + 9_000 });

    /* The oldest run has outlived the estimate: come back in a second. */
    const late = start + 30_000;
    expect(await admit('labA', 1, late)).toMatchObject({ admitted: false, estimated: true, retryAtMs: late + 1_000 });

    /* Durations longer than what is left of the run never pass its deadline. */
    for (let i = 0; i < 100; i++) {
      await admit('labC', 1, start, `long-${i}`);
      await releaseRun('labC', `long-${i}`, start + RUN_WALL_CAP_MS + 5_000 - 1);
    }
    expect(await admit('labA', 1, start + 3_000)).toMatchObject({ admitted: false, retryAtMs: start + RUN_WALL_CAP_MS });
  });

  test('a tenant far over its share is told when enough of its runs end to bring it back under', async () => {
    /* Ten earlier runs took 1..10 s (p90 = 9 s); labC is long quiet by `start`. */
    for (let i = 1; i <= 10; i++) {
      await admit('labC', 1, T0, `c-${i}`);
      await releaseRun('labC', `c-${i}`, T0 + i * 1_000);
    }
    const start = T0 + 10_000 + 10 * DEMAND_DECAY_MS;
    /* labA alone starts 4 runs a second apart; then labB arrives and labA's share drops to 2. */
    for (let i = 0; i < 4; i++) expect((await admit('labA', 1, start + i * 1_000)).admitted).toBe(true);
    expect((await admit('labB', 1, start + 4_000)).admitted).toBe(true);

    /* labA is back under its share once 3 of its 4 runs end: the third oldest started at start + 2 s. */
    expect(await admit('labA', 1, start + 5_000)).toMatchObject({
      admitted: false,
      share: 2,
      inFlight: 4,
      estimated: true,
      retryAtMs: start + 2_000 + 9_000,
    });
  });

  test('the pool is CODE_RUN_CAPACITY times the workers', async () => {
    env.CODE_RUN_CAPACITY = 2;
    env.CODE_WORKER_REPLICAS = 2;
    expect(poolCapacity()).toBe(4);
    await admit('labB', 1, T0);
    await admitMany('labA', 1, T0, 3);
    expect((await admit('labA', 1, T0)).admitted).toBe(false);

    /* A third worker grows the pool to 6: labA's share becomes 3 and its next run is spare capacity. */
    env.CODE_WORKER_REPLICAS = 3;
    expect(poolCapacity()).toBe(6);
    expect((await admit('labA', 1, T0)).admitted).toBe(true);
    expect(await inFlight('labA')).toBe(4);
  });

  test('a tenant arriving at a full engine is admitted at better priority while the busy tenant is refused', async () => {
    const a = await admitMany('labA', 3, T0, 8);
    expect(a.every(d => d.admitted)).toBe(true);

    const b1 = await admit('labB', 1, T0 + 1_000);
    expect(b1.admitted && b1.priority).toBe(UNDER_SHARE_PRIORITY);
    /* labB's run goes ahead of labA's queued over-share runs. */
    expect(a.slice(CAPACITY).every(d => d.admitted && d.priority === OVER_SHARE_PRIORITY)).toBe(true);
    expect(UNDER_SHARE_PRIORITY).toBeLessThan(OVER_SHARE_PRIORITY);

    expect((await admit('labB', 1, T0 + 1_000)).admitted).toBe(false);
    const a9 = await admit('labA', 3, T0 + 1_000);
    expect(a9.admitted).toBe(false);
    expect(!a9.admitted && a9.retryAtMs).toBe(T0 + RUN_WALL_CAP_MS);
  });

  test('a just-idle tenant keeps its predicted slice for the decay window, then reserves nothing', async () => {
    /* labB ran 2 runs for a minute and has just finished them. */
    await admit('labB', 1, T0, 'b-1');
    await admit('labB', 1, T0, 'b-2');
    const finishedAt = T0 + 60_000;
    await releaseRun('labB', 'b-1', finishedAt);
    await releaseRun('labB', 'b-2', finishedAt);
    expect(await inFlight('labB')).toBe(0);

    /* labA (same weight) floods right after: it gets its half, labB's half stays free. */
    const soon = finishedAt + 1_000;
    const a = await admitMany('labA', 1, soon, 3);
    expect(a.map(d => d.admitted)).toEqual([true, true, false]);

    /* labB returns within the window and finds its slice. */
    const b = await admitMany('labB', 1, soon + 5_000, 2);
    expect(b.every(d => d.admitted && d.priority === UNDER_SHARE_PRIORITY)).toBe(true);
    await releaseRun('labB', 'slot-4', soon + 6_000);
    await releaseRun('labB', 'slot-5', soon + 6_000);

    /* Long after labB went quiet its prediction has decayed: labA is alone again. */
    const later = soon + 6_000 + 5 * DEMAND_DECAY_MS;
    const lateA = await admitMany('labA', 1, later, 6);
    expect(lateA.every(d => d.admitted)).toBe(true);
  });

  test('runs past the wall cap leave by themselves', async () => {
    await admit('labB', 1, T0);
    /* labA fills the spare capacity, then stops at its share of 2. */
    expect((await admitMany('labA', 1, T0, 3)).every(d => d.admitted)).toBe(true);
    expect((await admit('labA', 1, T0 + 1_000)).admitted).toBe(false);
    expect((await admit('labB', 1, T0 + 1_000)).admitted).toBe(true);
    expect((await admit('labB', 1, T0 + 1_000)).admitted).toBe(false);

    /* Nobody released anything: every entry expires at its deadline. */
    const afterCap = T0 + 1_000 + RUN_WALL_CAP_MS + 1;
    expect((await admit('labA', 1, afterCap)).admitted).toBe(true);
    expect(await inFlight('labA')).toBe(1);
    expect(await inFlight('labB')).toBe(0);
  });

  test('continuations of an admitted run are counted but never refused', async () => {
    await admit('labB', 1, T0);
    await admitMany('labA', 1, T0, 3);
    expect((await admit('labA', 1, T0)).admitted).toBe(false);

    const continuation = await admitRun({ tenantId: 'labA', weight: 1, now: T0, slotId: 'cont', force: true });
    expect(continuation.admitted).toBe(true);
    expect(await inFlight('labA')).toBe(4);
  });
});

describe('fair-share startup', () => {
  test('an API instance drops only its own leftover slots', async () => {
    const now = Date.now();
    await admitRun({ tenantId: 'labA', weight: 1, now, slotId: 'mine-1' });
    await admitRun({ tenantId: 'labA', weight: 1, now, slotId: 'mine-2' });
    env.INSTANCE_ID = 'api-2';
    await admitRun({ tenantId: 'labA', weight: 1, now, slotId: 'theirs' });

    env.INSTANCE_ID = 'api-1';
    expect(await dropInstanceLeftovers()).toBe(2);
    expect(await redis.zrange(inflightKey('labA'), 0, -1)).toEqual(['api-2:theirs']);
  });

  test('the API refuses to start when the workers run another CODE_RUN_CAPACITY', async () => {
    /* First boot: no worker has published yet. */
    await expect(assertWorkerCapacityAgrees()).resolves.toBeUndefined();

    await publishWorkerCapacity();
    await expect(assertWorkerCapacityAgrees()).resolves.toBeUndefined();

    env.CODE_RUN_CAPACITY = CAPACITY + 1;
    await expect(assertWorkerCapacityAgrees({ waitMs: 100, pollMs: 10 })).rejects.toThrow(/Set CODE_RUN_CAPACITY to the same value/);
  });

  test('an API restarted with a new CODE_RUN_CAPACITY before the workers waits for them to publish it', async () => {
    await publishWorkerCapacity();
    /* The API has read the old workers' value once: the workers come up now. */
    const firstRead = Promise.withResolvers<void>();
    let reads = 0;
    setFairShareRedisForTests({
      eval: (script, numKeys, ...args) => redis.eval(script, numKeys, ...args),
      set: (key, value) => redis.set(key, value),
      async get(key) {
        const value = await redis.get(key);
        if (++reads === 1) firstRead.resolve();
        return value;
      },
    });
    /* Both get CODE_RUN_CAPACITY + 1; the API boots first. */
    env.CODE_RUN_CAPACITY = CAPACITY + 1;
    const starting = assertWorkerCapacityAgrees({ waitMs: 5_000, pollMs: 10 });
    await firstRead.promise;
    await publishWorkerCapacity();

    await expect(starting).resolves.toBeUndefined();
    expect(reads).toBeGreaterThan(1);
  });
});

describe('fair-share over HTTP', () => {
  type HeldRun = { finish(): void; released: Promise<void> };
  const servers: Server[] = [];
  let held: HeldRun[] = [];
  let nextRun = Promise.withResolvers<HeldRun>();

  afterEach(async () => {
    held.forEach(run => run.finish());
    held = [];
    nextRun = Promise.withResolvers<HeldRun>();
    await Promise.all(servers.splice(0).map((server) => {
      const { promise, resolve } = Promise.withResolvers<void>();
      server.closeAllConnections();
      server.close(() => resolve());
      return promise;
    }));
  });

  async function startApp(): Promise<string> {
    const app = express();
    app.use(express.json());
    app.use((req, _res, next) => {
      applyPrincipal(req as AuthenticatedRequest, {
        userId: 'user-1',
        tenantId: 'labA',
        principalSource: 'librechat_jwt',
        codeAgents: 1,
      });
      next();
    });
    app.post('/v1/exec', async (req, res) => {
      const admission = await admitRequestRun(req as AuthenticatedRequest, res, { slotId: String(req.header('x-slot')) });
      if (!admission) return;
      /* Holds the run until the test ends it. The release is memoized, so this
       * awaits the one admitRequestRun started. */
      const released = Promise.withResolvers<void>();
      const onEnd = (): void => {
        void admission.release().then(released.resolve);
      };
      res.once('finish', onEnd);
      res.once('close', onEnd);
      const run = {
        finish: () => {
          if (!res.writableEnded) res.status(200).json({ ok: true });
        },
        released: released.promise,
      };
      held.push(run);
      nextRun.resolve(run);
    });
    const server = app.listen(0, '127.0.0.1');
    servers.push(server);
    await once(server, 'listening');
    return `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
  }

  async function takeRun(): Promise<HeldRun> {
    const run = await nextRun.promise;
    nextRun = Promise.withResolvers<HeldRun>();
    return run;
  }

  test('a refused run gets 429 rate_limited / tenant_share_exceeded with Retry-After and retry_at', async () => {
    const url = await startApp();
    /* labB (weight 3) is busy; labA (weight 1) already holds its 1 of the 4 slots. */
    for (let i = 0; i < 3; i++) await admitRun({ tenantId: 'labB', weight: 3, slotId: `b-${i}` });
    expect((await admitRun({ tenantId: 'labA', weight: 1, slotId: 'a-0' })).admitted).toBe(true);

    const refused = await fetch(`${url}/v1/exec`, { method: 'POST', headers: { 'x-slot': 'a-1' } });
    const body = await refused.json() as Record<string, unknown>;

    expect(refused.status).toBe(429);
    expect(Number(refused.headers.get('retry-after'))).toBeGreaterThan(0);
    expect(body).toMatchObject({ error: 'rate_limited', reason: 'tenant_share_exceeded', share: 1, in_flight: 1 });
    expect(Date.parse(String(body.retry_at))).toBeGreaterThan(Date.now());
    expect(body.retry_after_seconds).toBe(Number(refused.headers.get('retry-after')));
    expect(String(body.message)).toMatch(/^The code engine is full and your company is using its share \(1 slot; 1 of its runs are running or queued\)\. A slot frees by \d\d:\d\d:\d\d UTC at the latest \(in about \d+ s\)\.$/);
    expect(await inFlight('labA')).toBe(1);
  });

  test('the slot is released when the response is sent', async () => {
    const url = await startApp();

    const finished = fetch(`${url}/v1/exec`, {
      method: 'POST',
      headers: { 'x-slot': 'done', 'content-type': 'application/json' },
      body: JSON.stringify({ lang: 'py', code: 'print(1)' }),
    });
    const run = await takeRun();
    expect(await inFlight('labA')).toBe(1);
    run.finish();
    expect((await finished).status).toBe(200);
    await run.released;
    expect(await inFlight('labA')).toBe(0);
  });
});
