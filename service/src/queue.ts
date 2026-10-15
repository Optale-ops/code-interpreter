// src/queue.ts
import IORedis from 'ioredis';
import { Queue, QueueEvents } from 'bullmq';
import { setMaxListeners } from 'events';
import type { CommonRedisOptions } from 'ioredis';
import type * as tls from 'tls';
import type * as t from './types';
import { Jobs } from './enum';
import { env } from './config';
import { queueNameForExecutionProfile } from './execution-profile';
import logger from './logger';
import { redisKeepAliveOptions } from './redis-options';
import { bullmqQueueJobs, registerBullmqQueueMetricsCollector } from './metrics';

const MAX_RECONNECT_ATTEMPTS = 5;
const RECONNECT_DELAY = 2000;

const retryStrategy: CommonRedisOptions['retryStrategy'] = (times) => {
  if (times > MAX_RECONNECT_ATTEMPTS) {
    logger.error(`Failed to connect to Redis after ${times} attempts`);
    return null;
  }
  logger.warn(`Retrying Redis connection attempt ${times}`);
  return RECONNECT_DELAY;
};

const reconnectOnError: CommonRedisOptions['reconnectOnError'] = (err) => {
  logger.error('Redis connection error:', err);
  const targetError = 'READONLY';
  if (err.message.includes(targetError)) {
    return true;
  }
  return false;
};

const connection = new IORedis({
  host: process.env.REDIS_HOST ?? 'redis',
  port: Number(process.env.REDIS_PORT) || 6379,
  password: process.env.REDIS_PASSWORD,
  maxRetriesPerRequest: null,
  retryStrategy,
  reconnectOnError,
  enableReadyCheck: true,
  connectTimeout: 10000,
  disconnectTimeout: 2000,
  ...redisKeepAliveOptions(),
  tls: process.env.REDIS_TLS === 'true' ? {
    rejectUnauthorized: false
  } as tls.ConnectionOptions : undefined,
  // Alternative DNS lookup for AWS ElastiCache TLS connections
  ...(env.REDIS_USE_ALTERNATIVE_DNS_LOOKUP
    ? { dnsLookup: (address: string, callback: (err: Error | null, addr: string) => void): void => callback(null, address) }
    : {})
});

// One global run queue - no INSTANCE_ID prefix
// Every code run, whatever its language, goes through it, so the workers and
// fair share see one shared pool. Any worker can process any job, while the
// execution-profile name prevents HTTP and Lambda workers from consuming each
// other's jobs when they share Redis.
const queueName = queueNameForExecutionProfile(
  env.EXECUTION_PROFILE,
  env.EXECUTION_PROFILE_SOURCE,
);
const runQueue = new Queue<t.JobData, t.JobResult, Jobs.execute>(queueName, { connection });
const runQueueEvents = new QueueEvents(queueName, { connection });

/* Fair-share jobs carry a BullMQ priority, so queued runs sit in `prioritized`
 * rather than `waiting`. */
const queueMetricStates = ['waiting', 'prioritized', 'active', 'delayed'] as const;
const QUEUE_METRICS_TIMEOUT_MS = 1000;

async function withTimeout<T>(promise: Promise<T>, timeoutMs: number, message: string): Promise<T> {
  let timeout: ReturnType<typeof setTimeout> | undefined;
  void promise.catch(() => undefined);
  const timeoutPromise = new Promise<never>((_, reject) => {
    timeout = setTimeout(() => reject(new Error(message)), timeoutMs);
  });
  try {
    return await Promise.race([promise, timeoutPromise]);
  } finally {
    if (timeout !== undefined) {
      clearTimeout(timeout);
    }
  }
}

registerBullmqQueueMetricsCollector(async () => {
  try {
    const counts = await withTimeout(
      runQueue.getJobCounts(...queueMetricStates),
      QUEUE_METRICS_TIMEOUT_MS,
      `Timed out collecting BullMQ queue metrics for ${queueName}`,
    );
    for (const state of queueMetricStates) {
      bullmqQueueJobs.set({ queue: queueName, state }, counts[state] ?? 0);
    }
  } catch (error) {
    logger.warn('Failed to collect BullMQ queue metrics', { queue: queueName, error });
    for (const state of queueMetricStates) {
      bullmqQueueJobs.remove({ queue: queueName, state });
    }
  }
});

/* job.waitUntilFinished() attaches a short-lived `closing` listener to the
 * shared Queue for every in-flight HTTP request waiting on a result. Bursts
 * above Node's default listener limit are normal for CodeAPI throughput, so
 * keep the leak warning enabled elsewhere while disabling it for these shared
 * BullMQ coordination objects. */
setMaxListeners(0, runQueue, runQueueEvents);

export { runQueue, runQueueEvents, queueName, connection };
