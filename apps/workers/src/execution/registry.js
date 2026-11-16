import { createEngineRegistry } from "./engines.js";
import { createSbomEngine } from "./engines/sbom/index.js";

/**
 * The engine registry of this process. SBOM is the ONLY engine registered (SPEC §17.ab, owner decision 2026-11-16): the
 * built-in inventory engine that reads package manifests and lockfiles as data. Every other scan type (SCA, SAST, secrets)
 * has no engine yet; a task of such a type is created `unsupported` (engine_not_registered) and never blocks the execution.
 * External-tool engines are a separate future module with its own sandbox ADR. The registry is only consulted when the
 * orchestrator flag is on (`EXECUTION_ORCHESTRATOR_ENABLED`); with the flag off nothing runs.
 */
export const engineRegistry = createEngineRegistry();
engineRegistry.register(createSbomEngine());
