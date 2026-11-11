import { QUEUE_NAMES, SCM_EVENTS_EXCHANGE } from "@qmentisai/contracts";
import { runWorker } from "../runtime/run-worker.js";
import { createWorkerGitHub } from "./github.js";
import { createScmEventHandler } from "./events.js";
import { createScmJobHandler } from "./jobs.js";

/** Entry point of the scm worker: GitHub jobs (queue `scm`) and the SCM event consumer (queue `scm-events`). */
export const WORKER_NAME = "scm";

/**
 * Starts the scm worker. Both consumers re-validate tenant and resource ownership against the database before handling
 * (platform-level jobs carry no tenant and skip the tenant checks). Needs the GitHub App settings and platform secrets.
 * @returns {Promise<{ stop: () => Promise<void> }>}
 */
export function start() {
  return runWorker({
    name: WORKER_NAME,
    queue: QUEUE_NAMES.SCM,
    buildHandler: ({ db, config, logger }) =>
      createScmJobHandler({ db, config, logger, github: createWorkerGitHub({ config, logger }) }),
    verifyOwnership: true,
    requireTenant: false,
    additional: [
      {
        queue: QUEUE_NAMES.SCM_EVENTS,
        buildHandler: ({ db, config, logger }) => createScmEventHandler({ db, config, logger }),
        verifyOwnership: true,
        bindings: [{ exchange: SCM_EVENTS_EXCHANGE, routingKey: "scm.github.#" }],
      },
    ],
  });
}
