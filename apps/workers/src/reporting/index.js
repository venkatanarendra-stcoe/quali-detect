import { QUEUE_NAMES } from "@qmentisai/contracts";
import {
  createDbClient,
  createReportingExportWorkerRepository,
  createReportingRollupRepository,
} from "@qmentisai/db";
import { runWorker } from "../runtime/run-worker.js";
import { createReportingHandler } from "./handlers.js";
import { startRollupTick } from "./rollup/index.js";

/** Entry point of the reporting worker (docs/modules/reporting-dashboards/SPEC.md 10, ADR-015). */
export const WORKER_NAME = "reporting";

/**
 * Starts the reporting worker: consumes the `reporting` queue (`reporting.rollup.requested`, `reporting.export.requested`). It starts ONLY
 * when `REPORTING_ENABLED=true` (default off): with the flag off nothing is queued by the module and this process does nothing. Messages are
 * validated against the catalogue, their tenant re-verified against the database and deduplicated before the dispatcher runs; the dispatcher
 * and this entry are frozen by Part A0 (the parts fill `rollup/index.js` and `export/index.js`).
 *
 * The rollup and export repositories use `REPORTING_DATABASE_URL`, the restricted login role of `qm_reporting` (SELECT on the `report_*_v`
 * views, INSERT and UPDATE on the `report_*` tables, nothing else). In production the worker REFUSES to start without it; in development,
 * when it is unset, the shared pool is used (still only through the frozen repositories) and a warning is logged. The shared pool is also
 * what the runtime uses for message idempotency and the ownership check, and what the tick uses for the outbox.
 * @param {{ NODE_ENV?: string, REPORTING_ENABLED?: string, REPORTING_DATABASE_URL?: string }} [env]
 * @returns {Promise<{ stop: () => Promise<void> }>}
 */
export async function start(env = process.env) {
  if (env.REPORTING_ENABLED !== "true") {
    console.log(
      "The reporting worker is disabled (REPORTING_ENABLED is not true); nothing started.",
    );
    return { stop: async () => {} };
  }
  if (env.NODE_ENV === "production" && !env.REPORTING_DATABASE_URL) {
    console.error(
      "Invalid environment configuration:\n  - REPORTING_DATABASE_URL: required in production (the restricted qm_reporting login role)",
    );
    process.exit(1);
  }
  /** Resources the worker owns; closed by the stop hook after the in-flight jobs finish. */
  const owned = [];
  /** The restricted client, built once (the handler and the tick share it); the shared pool in development when no URL is set. */
  let restricted;
  const clientFor = ({ db, config, logger }) => {
    if (restricted === undefined) {
      restricted = config.reporting.databaseUrl
        ? createDbClient({ datasourceUrl: config.reporting.databaseUrl })
        : null;
      if (restricted) owned.push(() => restricted.$disconnect());
      else
        logger.warn(
          "REPORTING_DATABASE_URL is not set: the reporting worker uses the shared database pool (development only; production refuses to start)",
        );
    }
    return restricted ?? db;
  };
  const repositories = (context) => {
    const client = clientFor(context);
    return {
      rollupRepository: createReportingRollupRepository({ db: client }),
      exportRepository: createReportingExportWorkerRepository({ db: client }),
    };
  };
  const build = (context) =>
    createReportingHandler({
      ...repositories(context),
      config: context.config,
      logger: context.logger,
    });
  let tick = null;
  const worker = await runWorker({
    name: WORKER_NAME,
    queue: QUEUE_NAMES.REPORTING,
    buildHandler: build,
    verifyOwnership: true,
    onReady: ({ db, config, logger }) => {
      tick = startRollupTick({ db, ...repositories({ db, config, logger }), config, logger });
      return async () => {
        await tick?.stop();
      };
    },
  });
  return {
    stop: async () => {
      await worker.stop();
      for (const close of owned.reverse()) await close().catch(() => {});
    },
  };
}
