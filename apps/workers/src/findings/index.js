import { QUEUE_NAMES } from "@qmentisai/contracts";
import { runWorker } from "../runtime/run-worker.js";
import { createFindingsIngestHandler } from "./handler.js";

/** Entry point of the findings worker (docs/modules/findings/SPEC.md 9.2). */
export const WORKER_NAME = "findings";

/**
 * Starts the findings worker: consumes the `findings` queue (the second outbox row of `pipeline.execution.completed`, IN-1) and ingests
 * the execution's results into findings. It starts ONLY when `FINDINGS_INGESTION_ENABLED=true` (default off): with the flag off the
 * orchestrator writes no row to the queue and this process does nothing. Messages are validated, their tenant and the execution chain
 * re-verified against the database, and deduplicated before the handler runs.
 * @returns {Promise<{ stop: () => Promise<void> }>}
 */
export async function start() {
  if (process.env.FINDINGS_INGESTION_ENABLED !== "true") {
    console.log(
      "The findings worker is disabled (FINDINGS_INGESTION_ENABLED is not true); nothing started.",
    );
    return { stop: async () => {} };
  }
  return runWorker({
    name: WORKER_NAME,
    queue: QUEUE_NAMES.FINDINGS,
    buildHandler: ({ db, config }) => createFindingsIngestHandler({ db, config }),
    verifyOwnership: true,
  });
}
