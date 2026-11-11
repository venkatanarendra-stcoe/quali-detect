import { QUEUE_NAMES } from "@qmentisai/contracts";
import { createNoopHandler } from "../handlers/noop.js";
import { runWorker } from "../runtime/run-worker.js";

/** Entry point of the usage worker (see docs/architecture/WORKER_ARCHITECTURE.md). */
export const WORKER_NAME = "usage";

/**
 * Starts the usage worker: consumes the `usage` queue with a no-op handler until a stop signal arrives.
 * Replace the handler when the usage module is implemented.
 * @returns {Promise<{ stop: () => Promise<void> }>}
 */
export function start() {
  return runWorker({ name: WORKER_NAME, queue: QUEUE_NAMES.USAGE, handler: createNoopHandler() });
}
