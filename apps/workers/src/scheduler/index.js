import { QUEUE_NAMES } from "@qmentisai/contracts";
import { NonRetryableError } from "@qmentisai/infra";
import { runWorker } from "../runtime/run-worker.js";
import { enqueuePlatformJob, enqueueSessionPurge, purgeSessions } from "./jobs.js";
import { createScheduleHandler } from "./schedules.js";

/** Entry point of the scheduler worker (see docs/architecture/WORKER_ARCHITECTURE.md). */
export const WORKER_NAME = "scheduler";

/**
 * The scheduler's job handler: platform jobs delivered through the messaging layer. Session purge (maintenance) and the due
 * pipeline schedules (`pipeline.schedules.due_requested`, SPEC pipelines-triggers §6.4).
 * @param {{ db: any, config?: any, logger?: any }} deps
 * @returns {(message: any, context: { log: any }) => Promise<void>}
 */
export function createSchedulerHandler({ db, config, logger }) {
  const schedules = createScheduleHandler({ db, config, logger });
  return async (message, { log }) => {
    if (message.type === "pipeline.schedules.due_requested") {
      await schedules(message, { log });
      return;
    }
    if (message.type !== "maintenance.sessions.purge_requested")
      throw new NonRetryableError(`The scheduler does not handle "${message.type}".`, {
        reason: "unsupported-message-type",
      });
    const result = await purgeSessions({ db, retentionSeconds: message.payload.retentionSeconds });
    log.info(
      { ...result, retentionSeconds: message.payload.retentionSeconds },
      "Expired and revoked sessions purged",
    );
  };
}

/**
 * Starts the scheduler worker: consumes the `scheduler` queue and, while running, enqueues the session purge job every
 * SCHEDULER_SESSION_PURGE_INTERVAL_SECONDS (once at startup too) through the transactional outbox; the outbox relay
 * delivers it back to this queue. Stops cleanly on SIGINT/SIGTERM.
 * @returns {Promise<{ stop: () => Promise<void> }>}
 */
export function start() {
  // The handler needs the worker's database client, which exists only once the runtime has built it.
  let db;
  let workerConfig;
  let workerLogger;
  return runWorker({
    name: WORKER_NAME,
    queue: QUEUE_NAMES.SCHEDULER,
    handler: (message, context) =>
      createSchedulerHandler({ db, config: workerConfig, logger: workerLogger })(message, context),
    requireTenant: false,
    onReady({ db: client, config, logger }) {
      db = client;
      workerConfig = config;
      workerLogger = logger;
      const {
        sessionPurgeIntervalSeconds: intervalSeconds,
        sessionRetentionSeconds: retentionSeconds,
      } = config.scheduler;
      const tick = () =>
        enqueueSessionPurge({ db, intervalSeconds, retentionSeconds }).catch((error) =>
          logger.error({ err: error }, "Could not enqueue the session purge job"),
        );
      void tick();
      const timers = [setInterval(tick, intervalSeconds * 1000)];
      // Pipeline schedules (SPEC pipelines-triggers §6.4): every tick one platform job; the time-bucket messageId makes several
      // scheduler instances produce ONE job, and the handler is naturally idempotent (the slot key).
      const scheduleSeconds = config.scheduler.scheduleTickSeconds;
      const scheduleTick = () =>
        enqueuePlatformJob({
          db,
          queue: QUEUE_NAMES.SCHEDULER,
          type: "pipeline.schedules.due_requested",
          prefix: "pipeline-schedules-due",
          intervalSeconds: scheduleSeconds,
          payload: (bucket) => ({ bucket }),
        }).catch((error) =>
          logger.error({ err: error }, "Could not enqueue the due pipeline schedules job"),
        );
      void scheduleTick();
      timers.push(setInterval(scheduleTick, scheduleSeconds * 1000));
      if (config.scm.enabled) {
        // GitHub reconciliation and retention (SPEC §6.5): the scm worker consumes these platform jobs.
        const schedule = (name, seconds, build) => {
          const run = () =>
            enqueuePlatformJob({
              db,
              queue: QUEUE_NAMES.SCM,
              intervalSeconds: seconds,
              ...build,
            }).catch((error) =>
              logger.error({ err: error, job: name }, "Could not enqueue a scheduled GitHub job"),
            );
          void run();
          timers.push(setInterval(run, seconds * 1000));
        };
        schedule("sync", config.scm.syncIntervalSeconds, {
          type: "scm.repositories.sync_requested",
          prefix: "scm-sync-all",
          payload: { intervalSeconds: config.scm.syncIntervalSeconds },
        });
        schedule("reconcile", config.scm.reconcileIntervalSeconds, {
          type: "scm.deliveries.reconcile_requested",
          prefix: "scm-reconcile",
          payload: {
            windowHours: config.scm.reconcileWindowHours,
            maxRedeliveries: config.scm.reconcileMaxRedeliveries,
          },
        });
        schedule("purge", 86400, {
          type: "maintenance.scm.purge_requested",
          prefix: "scm-purge",
          payload: { retentionDays: config.scm.deliveryRetentionDays },
        });
      }
      return async () => timers.forEach((timer) => clearInterval(timer));
    },
  });
}
