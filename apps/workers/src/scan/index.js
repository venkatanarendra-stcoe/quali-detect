import { QUEUE_NAMES } from "@qmentisai/contracts";
import { createNoopHandler } from "../handlers/noop.js";
import { runWorker } from "../runtime/run-worker.js";

/** Entry point of the scan worker (see docs/architecture/WORKER_ARCHITECTURE.md). */
export const WORKER_NAME = "scan";

/**
 * Starts the scan worker: consumes the `scan` queue with a no-op handler until a stop signal arrives.
 * Replace the handler when the scan module is implemented.
 * @returns {Promise<{ stop: () => Promise<void> }>}
 */
export function start() {
  return runWorker({ name: WORKER_NAME, queue: QUEUE_NAMES.SCAN, handler: createNoopHandler() });
}
