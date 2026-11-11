import { QUEUE_NAMES } from "@qmentisai/contracts";
import { createNotificationHandler } from "./handler.js";
import { runWorker } from "../runtime/run-worker.js";

/** Entry point of the notification worker (see docs/architecture/WORKER_ARCHITECTURE.md). */
export const WORKER_NAME = "notification";

/**
 * Starts the notification worker: consumes the `notification` queue until a stop signal arrives. Messages are validated,
 * their tenant and resources re-verified against the database, deduplicated through `processed_messages`, then handled.
 * @returns {Promise<{ stop: () => Promise<void> }>}
 */
export function start() {
  return runWorker({
    name: WORKER_NAME,
    queue: QUEUE_NAMES.NOTIFICATION,
    handler: createNotificationHandler(),
    verifyOwnership: true,
  });
}
