import { createEngineRegistry } from "./engines.js";
import { createSbomEngine } from "./engines/sbom/index.js";

/**
 * Builds an engine registry. The built-in SBOM inventory (`sbom-lite`, SPEC scan-engines 5.10, OQ-18) is ALWAYS the registered
 * default. Only a STRICTLY `true` `ensembleEnabled` (the ensemble rollout flag, off by default, D-12) lets
 * the scan worker replace the `sbom`/`default` entry with the ensemble engine (`createEnsembleEngine` is called then, never
 * otherwise), so a flag that is false, unset, a string or any other value changes nothing. There is no silent fallback from the
 * ensemble to the built-in engine at run time (SE-28).
 * @param {{ ensembleEnabled?: unknown, createEnsembleEngine?: () => any }} [options]
 */
export function buildEngineRegistry({ ensembleEnabled = false, createEnsembleEngine } = {}) {
  const registry = createEngineRegistry();
  registry.register(createSbomEngine());
  if (ensembleEnabled === true) {
    if (typeof createEnsembleEngine !== "function")
      throw new TypeError("the ensemble flag is on but no ensemble engine factory was given");
    registry.register(createEnsembleEngine());
  }
  return registry;
}

/**
 * The engine registry of this process. SBOM is the ONLY engine registered (SPEC §17.ab, owner decision 2026-11-16): the
 * built-in inventory engine that reads package manifests and lockfiles as data. Every other scan type (SCA, SAST, secrets)
 * has no engine yet; a task of such a type is created `unsupported` (engine_not_registered) and never blocks the execution.
 * The scan worker builds its own registry with {@link buildEngineRegistry} when the ensemble flag is on; the pipeline worker only
 * asks `has(scanType, engineId)`, which is true either way. The registry is only consulted when the orchestrator flag is on
 * (`EXECUTION_ORCHESTRATOR_ENABLED`); with the flag off nothing runs.
 */
export const engineRegistry = buildEngineRegistry();
