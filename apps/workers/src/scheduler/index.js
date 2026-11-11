import { QUEUE_NAMES } from "@qmentisai/contracts";
import { createNoopHandler } from "../handlers/noop.js";
import { runWorker } from "../runtime/run-worker.js";

/** Entry point of the scheduler worker (see docs/architecture/WORKER_ARCHITECTURE.md). */
export const WORKER_NAME = "scheduler";

/**
 * Starts the scheduler worker: consumes the `scheduler` queue with a no-op handler until a stop signal arrives.
 * Replace the handler when the scheduler module is implemented.
 * @returns {Promise<{ stop: () => Promise<void> }>}
 */
export function start() {
  return runWorker({
    name: WORKER_NAME,
    queue: QUEUE_NAMES.SCHEDULER,
    handler: createNoopHandler(),
  });
}
