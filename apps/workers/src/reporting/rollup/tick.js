import { QUEUE_NAMES, createJobEnvelope } from "@qmentisai/contracts";
import { createOutboxRepository } from "@qmentisai/db";
import { createOutbox } from "@qmentisai/infra";
import {
  REPORTING_LIMITS,
  REPORTING_MESSAGE_TYPES,
  addDays,
  isValidTimeZone,
  localDayOf,
} from "@qmentisai/shared";
import { subtractMonths } from "./job.js";

/**
 * The hourly tick of the rollup (docs/modules/reporting-dashboards/SPEC.md 7.2, 10): ONE `reporting.rollup.requested` per usable tenant per
 * hour through the transactional outbox (ADR-011), the day close of every tenant whose previous local day has no succeeded close (so it
 * goes out right after each tenant-local midnight and keeps going until it succeeded), the first-enablement backfill of a tenant that was
 * never rolled up, and the retention purge (daily). The message ids are deterministic (`reporting-rollup-<tenant>-<mode>-<day>-<hour>`), and
 * the outbox is unique per (messageId, queue), so a second scheduler instance or a repeated tick queues nothing new. Called only when the
 * module is enabled: with `REPORTING_ENABLED=false` it starts nothing, so nothing is queued or written.
 */

export const TICK_INTERVAL_MS = 60 * 60 * 1000;
const TENANT_PAGE = 200;
const PURGE_LIMIT = 5000;
const PURGE_MAX_CALLS = 20;
const PURGE_EVERY_MS = 24 * 60 * 60 * 1000;
const MONTH_MS = 30.4375 * 24 * 60 * 60 * 1000;

/** The deterministic message id: `<tenant>-<mode>-<day>-<hour>`; `hour` is the epoch hour (unique, unlike a local hour on a fall-back day). */
export const rollupMessageId = (tenantId, mode, day, hourBucket) =>
  `reporting-rollup-${tenantId}-${mode}-${day}-${hourBucket}`;

/**
 * Enqueues one rollup message for a tenant through the outbox (idempotent per message id).
 * @param {any} db the shared pool @param {string} tenantId @param {string} messageId @param {Record<string, string>} payload
 */
async function enqueue(db, tenantId, messageId, payload) {
  const outbox = createOutbox({ repository: createOutboxRepository({ db }) });
  return db.$transaction((tx) =>
    outbox.enqueue(tx, {
      queue: QUEUE_NAMES.REPORTING,
      message: createJobEnvelope({
        messageId,
        type: REPORTING_MESSAGE_TYPES.ROLLUP_REQUESTED,
        schemaVersion: 1,
        tenantId,
        initiator: { type: "system", id: "reporting-tick" },
        payload: { tenantId, reason: "scheduled", ...payload },
      }),
    }),
  );
}

/**
 * One tick over every usable tenant. Exported for tests and for an operator; `startRollupTick` calls it on a timer.
 * @param {{ db: any, rollupRepository: any, config: any, logger: any, now?: () => Date }} deps
 * @returns {Promise<{ tenants: number, queued: number }>}
 */
export async function runTick({
  db,
  rollupRepository: repo,
  config,
  logger,
  now = () => new Date(),
}) {
  const instant = now();
  const hour = Math.floor(instant.getTime() / 3_600_000);
  const months = config?.reporting?.rollupRetentionMonths ?? REPORTING_LIMITS.rollupRetentionMonths;
  let tenants = 0;
  let queued = 0;
  let after;
  for (;;) {
    const page = await repo.listActiveTenants({ limit: TENANT_PAGE, afterTenantId: after });
    for (const { tenantId, timeZone } of page) {
      tenants += 1;
      try {
        if (!isValidTimeZone(timeZone)) {
          logger.warn(
            { tenantId },
            "reporting tick: the tenant time zone is not valid, tenant skipped",
          );
          continue;
        }
        const today = localDayOf(instant, timeZone);
        const yesterday = addDays(today, -1);
        await enqueue(db, tenantId, rollupMessageId(tenantId, "incremental", today, hour), {
          mode: "incremental",
          day: today,
        });
        queued += 1;
        // the close of the previous local day, until one succeeded (right after each tenant-local midnight)
        const closes = await repo.listRuns({
          tenantId,
          from: yesterday,
          to: yesterday,
          mode: "close",
        });
        if (!closes.some((r) => r.status === "succeeded" && r.day === yesterday)) {
          await enqueue(db, tenantId, rollupMessageId(tenantId, "close", yesterday, hour), {
            mode: "close",
            day: yesterday,
          });
          queued += 1;
        }
        // first enablement: never rolled up and has history: backfill from the earliest history day, capped at the retention
        const ever = await repo.findLatestRun({ tenantId });
        if (!ever) {
          const earliest = await repo.earliestHistoryAt({ tenantId });
          if (earliest) {
            const floor = subtractMonths(today, months);
            const first = localDayOf(earliest, timeZone);
            await enqueue(db, tenantId, rollupMessageId(tenantId, "backfill", today, hour), {
              mode: "backfill",
              from: first < floor ? floor : first,
              to: today,
              reason: "first_enablement",
            });
            queued += 1;
          }
        }
      } catch (error) {
        logger.error(
          { err: error, tenantId },
          "reporting tick: could not queue the rollup of a tenant",
        );
      }
    }
    if (page.length < TENANT_PAGE) break;
    after = page[page.length - 1].tenantId;
  }
  return { tenants, queued };
}

/**
 * The retention purge (SPEC 8.6): rollup rows older than the retention months, run rows older than 13 months, export rows older than 13
 * months, through the SECURITY DEFINER function, in bounded calls.
 * @param {{ rollupRepository: any, config: any, logger: any, now?: () => Date }} deps @returns {Promise<number>} rows removed
 */
export async function runPurge({ rollupRepository: repo, config, logger, now = () => new Date() }) {
  const instant = now();
  const months = config?.reporting?.rollupRetentionMonths ?? REPORTING_LIMITS.rollupRetentionMonths;
  const rollupBefore = subtractMonths(localDayOf(instant, "UTC"), months);
  const cutoff = new Date(instant.getTime() - REPORTING_LIMITS.runRetentionMonths * MONTH_MS);
  let removed = 0;
  for (let i = 0; i < PURGE_MAX_CALLS; i += 1) {
    const n = await repo.purgeExpired({
      rollupBefore,
      runsBefore: cutoff,
      exportsBefore: cutoff,
      limit: PURGE_LIMIT,
    });
    removed += n;
    if (n === 0) break;
  }
  if (removed > 0) logger.info({ removed }, "reporting retention purge finished");
  return removed;
}

/**
 * @param {import("./index.js").ReportingWorkerDeps & { db: any }} deps
 * @returns {{ stop: () => Promise<void> } | null}
 */
export function buildRollupTick(deps) {
  const { config, logger, now = () => new Date() } = deps;
  if (config?.reporting?.enabled !== true) return null; // OFF: nothing is queued or written
  let running = false;
  let lastPurge = 0;
  const tick = async () => {
    if (running) return;
    running = true;
    try {
      const result = await runTick(deps);
      logger.info(result, "reporting tick queued the rollups");
      if (now().getTime() - lastPurge >= PURGE_EVERY_MS) {
        await runPurge(deps);
        lastPurge = now().getTime();
      }
    } catch (error) {
      logger.error({ err: error }, "reporting tick failed");
    } finally {
      running = false;
    }
  };
  void tick();
  const timer = setInterval(tick, TICK_INTERVAL_MS);
  timer.unref?.();
  return {
    stop: async () => {
      clearInterval(timer);
    },
  };
}
