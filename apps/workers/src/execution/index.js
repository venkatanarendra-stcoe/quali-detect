import { createExecutionArtifactRepository } from "@qmentisai/db";
import { createLocalArtifactStore, createPostgresArtifactStore } from "@qmentisai/infra";
import { createWorkerGitHub } from "../scm/github.js";
import { createDecisionAgentRuntime } from "./decision/index.js";
import { createOrchestrator } from "./orchestrator.js";
import { buildPipelineEngineRegistry, engineRegistry } from "./registry.js";

export { createEngineRegistry, EngineError } from "./engines.js";
export { buildEngineRegistry, buildPipelineEngineRegistry, engineRegistry } from "./registry.js";
export { createOrchestrator } from "./orchestrator.js";
export { createScanTaskHandler, normalizeItems } from "./scan-handler.js";

/**
 * Builds the orchestrator of the pipeline worker from the worker context (GitHub App client, local artifact store, registry, and
 * the decision agent runtime of scan decisioning: with `LLM_PROVIDER=none` it resolves no provider and every decision is the floor).
 */
export function buildPipelineOrchestrator({ db, config, logger }) {
  return createOrchestrator({
    db,
    config,
    logger,
    github: createWorkerGitHub({ config, logger }),
    store: createLocalArtifactStore({ root: config.execution.artifactStoreRoot }),
    engines: config.scanEngines.ensembleEnabled
      ? buildPipelineEngineRegistry({ ensembleEnabled: true })
      : engineRegistry,
    decisionRuntime: createDecisionAgentRuntime({ db, config, logger }),
    // only used while the ensemble flag is on (the changed-paths artifact, scan engines part K core)
    artifacts: config.scanEngines.ensembleEnabled
      ? createPostgresArtifactStore({ repository: createExecutionArtifactRepository({ db }) })
      : null,
  });
}
