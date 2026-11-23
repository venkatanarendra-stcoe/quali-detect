import { notImplemented } from "./not-implemented.js";

/**
 * @typedef {{ tenantId: string, workspaceId: string, repositoryId: string, pipelineId: string, executionId: string }} ExecutionChain
 */

/**
 * Ingestion data access for the `findings` worker (Part A1, SPEC 5.3, IN-2, IN-4). Everything is loaded from the database by tenant,
 * workspace, repository, pipeline and execution id: the message is only a wake-up.
 * @param {{ db: any }} deps
 */
export function createFindingsIngestionRepository({ db }) {
  void db;
  return Object.freeze({
    /** Loads the verified execution facts of `IngestionExecutionFacts` (chain, trust, ref, scan kind, result, tool runs, markers); null when the chain does not match. @type {(ids: ExecutionChain, scanType: string) => Promise<import("@qmentisai/shared").IngestionExecutionFacts | null>} */
    loadExecutionFacts: notImplemented("A1", "ingestion.loadExecutionFacts"),
    /** The observed items of one result (items joined with their details). @type {(ids: { tenantId: string, executionId: string, scanResultId: string }) => Promise<import("@qmentisai/shared").ObservedItem[]>} */
    loadObservedItems: notImplemented("A1", "ingestion.loadObservedItems"),
    /** Existing findings of one pipeline and scan type (every status). @type {(ids: { tenantId: string, pipelineId: string, scanType: string }, tx?: any) => Promise<import("@qmentisai/shared").ExistingFinding[]>} */
    loadExisting: notImplemented("A1", "ingestion.loadExisting"),
    /** Applies a plan of `planIngestion` in the caller's transaction under the pipeline advisory lock and records the `finding_ingestions` row. @type {(tx: any, plan: object, facts: object) => Promise<{ replayed: boolean }>} */
    applyPlan: notImplemented("A1", "ingestion.applyPlan"),
  });
}
