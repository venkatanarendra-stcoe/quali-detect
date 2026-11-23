import { notImplemented } from "./not-implemented.js";

/**
 * The ONLY module the false-positive agent's worker may import from this package (SPEC 9.3.4 layer 2; the suite scans the import graph
 * of `apps/workers/src/findings-agent/`). Reads go through the `fp_agent_findings` view (secret findings are not in it: the agent does
 * not run on secrets in v1); the one write is `insertAdvisory`. It has no method that changes finding state, a review, an approval, an
 * assignment or the outbox, and it must work with the restricted `qm_fp_agent` role (FINDINGS_AGENT_DATABASE_URL). Part A1 implements
 * it; Part D uses it.
 * @param {{ db: any }} deps
 */
export function createFindingsAgentRepository({ db }) {
  void db;
  return Object.freeze({
    /** The finding as the agent may see it, by tenant, workspace and id, with the chain ids of the message verified against the row. Null on any mismatch. @type {(ids: { tenantId: string, workspaceId: string, repositoryId: string, pipelineId: string, findingId: string }) => Promise<object | null>} */
    getFindingForAdvisory: notImplemented("A1", "agent.getFindingForAdvisory"),
    /** The tenant's two consent flags, read by the tenant id of the FINDING ROW (never of the message). @type {(scope: { tenantId: string }) => Promise<{ externalConsent: boolean, codeSnippetConsent: boolean }>} */
    readConsent: notImplemented("A1", "agent.readConsent"),
    /** The advisory with this input hash, if any (idempotence). @type {(scope: { tenantId: string }, findingId: string, inputHash: string) => Promise<object | null>} */
    findAdvisoryByHash: notImplemented("A1", "agent.findAdvisoryByHash"),
    /** Counts the tenant's advisories since a time (the daily cap). @type {(scope: { tenantId: string }, since: Date) => Promise<number>} */
    countAdvisoriesSince: notImplemented("A1", "agent.countAdvisoriesSince"),
    /** The single write: one `finding_ai_advisories` row (the UNIQUE (finding, input hash) makes a replay a no-op). @type {(row: object) => Promise<{ id: string, created: boolean }>} */
    insertAdvisory: notImplemented("A1", "agent.insertAdvisory"),
  });
}
