import { QUEUE_NAMES } from "@qmentisai/contracts";
import { createNoopHandler } from "../handlers/noop.js";
import { buildPipelineOrchestrator } from "../execution/index.js";
import { runWorker } from "../runtime/run-worker.js";
import { createPipelineTriggerHandler } from "./router.js";

/** Entry point of the pipeline worker (see docs/architecture/WORKER_ARCHITECTURE.md). */
export const WORKER_NAME = "pipeline";

/**
 * The handler of queue `pipeline`: the no-op handler unless the orchestrator flag is on (then `build` is not even called).
 * @param {{ config: any }} context @param {(context: any) => { handler: Function }} build
 */
export function selectPipelineHandler(context, build) {
  return context.config.execution.enabled ? build(context).handler : createNoopHandler();
}

/**
 * Starts the pipeline worker. Two consumers run in this process:
 * - queue `pipeline-triggers`: the TRIGGER ROUTER (docs/modules/pipelines-triggers/SPEC.md §6.2). Bound to the SCM events topic
 *   exchange with `scm.github.push` and `scm.github.pull_request`; every message is ownership-verified against the database
 *   (tenant, workspace, repository) before the router runs, and the router re-checks the repository, workspace and tenant state;
 * - queue `pipeline`: execution requests (`pipeline.execution.requested`), scan completions and cancel wake-ups. With
 *   `EXECUTION_ORCHESTRATOR_ENABLED=false` (the default, EXEC-026) this queue keeps its no-op handler and nothing claims a
 *   queued execution (the `queued` row is the source of truth, SPEC §13.2). With the flag on, the EXECUTION ORCHESTRATOR
 *   (docs/modules/executions/SPEC.md part C) handles the queue, every message is ownership-verified, and a sweeper/heartbeat
 *   ticker claims, prepares, drives and recovers executions.
 * @returns {Promise<{ stop: () => Promise<void> }>}
 */
export function start() {
  let orchestrator = null;
  const orchestratorOf = (context) => (orchestrator ??= buildPipelineOrchestrator(context));
  return runWorker({
    name: WORKER_NAME,
    queue: QUEUE_NAMES.PIPELINE,
    buildHandler: (context) => selectPipelineHandler(context, orchestratorOf),
    verifyOwnership: (config) => config.execution.enabled,
    additional: [
      {
        queue: QUEUE_NAMES.PIPELINE_TRIGGERS,
        buildHandler: ({ db, config, logger }) =>
          createPipelineTriggerHandler({ db, config, logger }),
        verifyOwnership: true,
      },
    ],
    onReady: (context) =>
      context.config.execution.enabled ? orchestratorOf(context).start() : undefined,
  });
}
