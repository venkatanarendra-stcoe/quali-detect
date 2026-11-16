import { createEngineRegistry } from "./engines.js";

/**
 * The engine registry of this process. EMPTY in production on purpose (no engine ships yet, EXEC-026): the orchestrator
 * claims only executions whose enabled scan types have a registered engine. The Scan engine integration module registers
 * its adapters here.
 */
export const engineRegistry = createEngineRegistry();
