import { PIPELINE_TRIGGERS_BINDINGS, QUEUE_NAMES } from "@qmentisai/contracts";
import { createNoopHandler } from "../handlers/noop.js";
import { runWorker } from "../runtime/run-worker.js";
import { createPipelineTriggerHandler } from "./router.js";

/** Entry point of the pipeline worker (see docs/architecture/WORKER_ARCHITECTURE.md). */
export const WORKER_NAME = "pipeline";

/**
 * Starts the pipeline worker. Two consumers run in this process:
 * - queue `pipeline-triggers`: the TRIGGER ROUTER (docs/modules/pipelines-triggers/SPEC.md §6.2). Bound to the SCM events topic
 *   exchange with `scm.github.push` and `scm.github.pull_request`; every message is ownership-verified against the database
 *   (tenant, workspace, repository) before the router runs, and the router re-checks the repository, workspace and tenant state;
 * - queue `pipeline`: execution requests (`pipeline.execution.requested`). The execution lifecycle module is not built yet, so
 *   this queue keeps its no-op handler (the `queued` row is the source of truth, SPEC §13.2).
 * @returns {Promise<{ stop: () => Promise<void> }>}
 */
export function start() {
  return runWorker({
    name: WORKER_NAME,
    queue: QUEUE_NAMES.PIPELINE,
    handler: createNoopHandler(),
    additional: [
      {
        queue: QUEUE_NAMES.PIPELINE_TRIGGERS,
        buildHandler: ({ db, config, logger }) =>
          createPipelineTriggerHandler({ db, config, logger }),
        verifyOwnership: true,
        bindings: [...PIPELINE_TRIGGERS_BINDINGS],
      },
    ],
  });
}
