import { createLocalArtifactStore } from "@qmentisai/infra";
import { createWorkerGitHub } from "../scm/github.js";
import { createOrchestrator } from "./orchestrator.js";
import { engineRegistry } from "./registry.js";

export { createEngineRegistry, EngineError } from "./engines.js";
export { engineRegistry } from "./registry.js";
export { createOrchestrator } from "./orchestrator.js";
export { createScanTaskHandler, normalizeItems } from "./scan-handler.js";

/** Builds the orchestrator of the pipeline worker from the worker context (GitHub App client, local artifact store, registry). */
export function buildPipelineOrchestrator({ db, config, logger }) {
  return createOrchestrator({
    db,
    config,
    logger,
    github: createWorkerGitHub({ config, logger }),
    store: createLocalArtifactStore({ root: config.execution.artifactStoreRoot }),
    engines: engineRegistry,
  });
}
