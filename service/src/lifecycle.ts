import type { Queue } from 'bullmq';
import type { Express } from 'express';
import { runQueue, runQueueEvents, connection } from './queue';
import { validateStartupAuthConfig } from './auth/startup';
import { env } from './config';
import {
  validateApiHardenedConfig,
  validateExecutionProfilePolicy,
  validateSandboxBackendPolicy,
  validateWorkerHardenedConfig,
} from './secure-startup';
import logger from './logger';
import { shutdownTelemetry } from './telemetry';
import { configureExecutionProfileMetrics } from './metrics';
import { assertWorkerCapacityAgrees, dropInstanceLeftovers, publishWorkerCapacity } from './fair-share';

const { INSTANCE_ID } = env;
let isShuttingDown = false;
let isStartingUp = true;

function configureProfileMetrics(): void {
  configureExecutionProfileMetrics({
    profile: env.EXECUTION_PROFILE,
    sandboxBackend: env.SANDBOX_BACKEND,
    runtimeSessionMode: env.RUNTIME_SESSION_MODE,
  });
}

async function shutdownTracing(): Promise<void> {
  try {
    await shutdownTelemetry();
    logger.info('OpenTelemetry shutdown completed');
  } catch (error) {
    logger.warn('OpenTelemetry shutdown failed', { error });
  }
}

async function validateLifecycleAuthConfig(): Promise<void> {
  await validateStartupAuthConfig();
}

// Flag to track if this process runs workers
let hasWorkers = false;

/**
 * Register that this process has workers running.
 * Called by worker entry points to enable worker-specific shutdown behavior.
 */
export function registerWorkers(): void {
  hasWorkers = true;
}

/**
 * Set up queue event listeners for monitoring
 */
function setupQueueListeners(queue: Queue, name: string): void {
  queue.on('error', (error: Error) => {
    logger.error(`${name} queue error:`, error);
  });

  queue.on('waiting', (job) => {
    logger.debug(`${name} job ${job.id} waiting`);
  });

  queue.on('progress', (job, progress) => {
    logger.debug(`${name} job progress:`, { job, progress });
  });

  queue.on('paused', () => {
    logger.info(`${name} queue paused`);
  });

  queue.on('resumed', () => {
    logger.info(`${name} queue resumed`);
  });

  queue.on('removed', (jobId) => {
    logger.debug(`${name} job ${jobId} removed`);
  });

  queue.on('cleaned', (jobs, type) => {
    logger.info(`${name} queue cleaned ${jobs.length} ${type} jobs`);
  });
}

/**
 * Startup for API-only mode (no workers)
 * Just validates authentication and sets up queue connections for job submission
 */
export async function startupApiOnly(): Promise<void> {
  logger.info('Starting API service (no workers)...');
  validateApiHardenedConfig();
  validateExecutionProfilePolicy({ requireBackendMatch: false });
  /* No validateSandboxBackendPolicy() here: an API-only pod authenticates and
   * enqueues jobs, it never constructs the Lambda backend or checkpoint store.
   * Validating that policy would force worker-only config (LAMBDA_MICROVM_* and
   * the MINIO_* checkpoint creds) into API pods just to boot. The worker and
   * combined startups own that validation. */
  await validateLifecycleAuthConfig();
  await assertWorkerCapacityAgrees();
  await dropInstanceLeftovers();
  configureProfileMetrics();

  // Set up queue listeners for monitoring (optional, for observability)
  setupQueueListeners(runQueue, 'Run');

  isStartingUp = false;
  logger.info('API service startup complete');
}

/**
 * Startup for Worker-only mode
 * Imports workers and validates they're running
 */
export async function startupWorkerOnly(): Promise<void> {
  logger.info('Starting Worker service...');
  validateWorkerHardenedConfig();
  validateExecutionProfilePolicy();
  validateSandboxBackendPolicy();
  configureProfileMetrics();

  // Dynamically import the worker to start it
  const { runWorker } = await import('./workers');

  registerWorkers();
  await publishWorkerCapacity();

  // Verify the worker is running
  const checkWorkers = (): void => {
    if (!runWorker.isRunning()) {
      throw new Error('Run worker is not running');
    }
    logger.info('Workers health check passed');
  };

  checkWorkers();
  isStartingUp = false;
  logger.info('Worker service startup complete');
}

/**
 * Combined startup for backward compatibility (API + Workers in same process)
 * This is the legacy mode used by service-api.ts
 */
async function gracefulStartup(): Promise<void> {
  logger.info('Starting up service (combined API + Workers)...');
  validateApiHardenedConfig();
  validateWorkerHardenedConfig();
  validateExecutionProfilePolicy();
  validateSandboxBackendPolicy();
  await validateLifecycleAuthConfig();
  configureProfileMetrics();

  try {
    logger.info('Setting up queues...');

    // Import the worker (this starts it)
    const { runWorker } = await import('./workers');

    registerWorkers();
    await publishWorkerCapacity();
    await dropInstanceLeftovers();

    // Set up queue event listeners
    setupQueueListeners(runQueue, 'Run');

    // Verify the worker is running
    const checkWorkers = (): void => {
      if (!runWorker.isRunning()) {
        throw new Error('Run worker is not running');
      }
      logger.info('Workers health check passed');
    };

    checkWorkers();

    // Resume the queue (in case it was paused)
    await runQueue.resume();

    isStartingUp = false;
    logger.info('Service startup complete');
  } catch (error) {
    logger.error('Error during startup:', error);
    throw error;
  }
}

/**
 * Graceful shutdown - handles both API-only and Worker modes
 *
 * Key changes for scalability:
 * - Does NOT drain or clean shared queues (other workers may be processing)
 * - Only closes this instance's workers gracefully
 * - Waits for active jobs to complete before closing workers
 */
export async function gracefulShutdown(): Promise<void> {
  if (isShuttingDown) return;
  isShuttingDown = true;

  logger.info('Initiating graceful shutdown...');

  const shutdownTimeout = setTimeout(() => {
    logger.error('Shutdown timeout reached, forcing exit');
    process.exit(1);
  }, 30000);

  try {
    if (hasWorkers) {
      // Worker shutdown: close the worker gracefully
      const { runWorker } = await import('./workers');

      // Pause the worker and wait for active jobs to complete
      // Note: We pause the worker, NOT the queue (the queue is shared)
      // pause(false) = wait for active jobs to finish before resolving (doNotWaitActive=false)
      // pause(true) = return immediately without waiting for active jobs
      logger.info('Pausing Run worker and waiting for active jobs to drain...');
      try {
        // doNotWaitActive=false means wait for active jobs to complete
        await runWorker.pause(false);
        logger.info('Run worker drained successfully');
      } catch (error) {
        logger.warn('Run worker pause failed', { error });
      }

      await runWorker.close();
      logger.info('Workers closed');
    }

    // Close queue connections (both API and Worker need this)
    await Promise.all([
      runQueue.close(),
      runQueueEvents.close()
    ]);
    logger.info('Queue connections closed');

    // Only disconnect Redis if explicitly requested
    if (process.env.FORCE_REDIS_DISCONNECT === 'true') {
      connection.disconnect();
      logger.info('Redis connection closed');
    }

    await shutdownTracing();

    clearTimeout(shutdownTimeout);
    logger.info('Graceful shutdown completed');
    process.exit(0);
  } catch (error) {
    logger.error('Error during shutdown:', error);
    await shutdownTracing();
    clearTimeout(shutdownTimeout);
    process.exit(1);
  }
}

export function checkServiceStartUp(): boolean {
  return isStartingUp;
}

export function setStartupComplete(): void {
  isStartingUp = false;
}

export function checkServiceShutDown(): boolean {
  return isShuttingDown;
}

/**
 * Start combined server (API + Workers) - for backward compatibility
 */
export async function startServer(app: Express, callback?: () => Promise<void>): Promise<void> {
  try {
    await gracefulStartup();
    app.listen(env.PORT, () => {
      logger.info(`[${INSTANCE_ID}] Server is running on port ${env.PORT}`);
      logger.info(`[${INSTANCE_ID}] CODE_RUN_CAPACITY: ${env.CODE_RUN_CAPACITY} | JOB_WINDOW: ${env.JOB_WINDOW}`);
    });

    if (callback != null) {
      await callback();
    }
  } catch (error) {
    logger.error('Failed to start server:', error);
    process.exit(1);
  }
}

/**
 * Start API-only server (no workers)
 */
export async function startApiServer(app: Express, callback?: () => Promise<void>): Promise<void> {
  try {
    await startupApiOnly();
    app.listen(env.PORT, () => {
      logger.info(`[${INSTANCE_ID}] API Server is running on port ${env.PORT}`);
      logger.info(`[${INSTANCE_ID}] Mode: API-only (no workers)`);
    });

    if (callback != null) {
      await callback();
    }
  } catch (error) {
    logger.error('Failed to start API server:', error);
    process.exit(1);
  }
}

/**
 * Start Worker-only server (no HTTP)
 */
export async function startWorkerServer(callback?: () => Promise<void>): Promise<void> {
  try {
    await startupWorkerOnly();
    logger.info(`[${INSTANCE_ID}] Worker Server started`);
    logger.info(`[${INSTANCE_ID}] CODE_RUN_CAPACITY: ${env.CODE_RUN_CAPACITY} | JOB_WINDOW: ${env.JOB_WINDOW}`);

    if (callback != null) {
      await callback();
    }
  } catch (error) {
    logger.error('Failed to start worker server:', error);
    process.exit(1);
  }
}
