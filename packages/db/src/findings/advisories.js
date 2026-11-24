import { FINDINGS_LIMITS, agentRunsOn } from "@qmentisai/shared";
import { FindingNotFoundError } from "./errors.js";
import {
  FINDING_QUEUES,
  buildFindingMessage,
  enqueueFindingMessages,
  initiatorOf,
} from "./events.js";

const HOUR_MS = 3_600_000;

const ADVISORY_COLUMNS = Object.freeze({
  id: true,
  findingId: true,
  status: true,
  suggestion: true,
  confidence: true,
  reasoning: true,
  egressLevel: true,
  provider: true,
  model: true,
  createdAt: true,
});

/**
 * Advisory reads and the manual re-request for the API (Part D, docs/modules/findings/SPEC.md 8, 9.3.5). The agent itself uses
 * `agent-repository.js` (a different connection and role). Every method takes the trusted `{ tenantId, workspaceId }` scope; nothing is
 * read or written by id alone. The advisory rows are written ONLY by the agent: the one write here is a `finding.advisory.requested` job
 * for the outbox (in the caller's transaction), which carries ids and the word `manual`.
 * @param {{ db: any }} deps
 */
export function createFindingAdvisoriesRepository({ db }) {
  /** @param {{ tenantId: string, workspaceId: string }} scope */
  const where = (scope, findingId) => ({
    tenantId: scope.tenantId,
    workspaceId: scope.workspaceId,
    findingId,
  });

  /** Counts the manual requests in the last hour (outbox rows of this tenant: sent rows are kept for days). */
  async function countManual(client, scope, findingId, userId, now) {
    const since = new Date(now.getTime() - HOUR_MS);
    const [row] = await client.$queryRaw`
      SELECT
        count(*) FILTER (WHERE payload->'payload'->>'findingId' = ${findingId})::int AS per_finding,
        count(*) FILTER (WHERE payload->'initiator'->>'id' = ${userId})::int AS per_user
      FROM outbox_messages
      WHERE tenant_id = ${scope.tenantId}::uuid AND queue = ${FINDING_QUEUES.FINDINGS_AGENT}
        AND type = 'finding.advisory.requested' AND payload->'payload'->>'reason' = 'manual'
        AND created_at > ${since}`;
    return { perFinding: row?.per_finding ?? 0, perUser: row?.per_user ?? 0 };
  }

  return Object.freeze({
    /**
     * The latest advisory of a finding, or null.
     * @type {(scope: import("./transitions.js").FindingScope, findingId: string) => Promise<object | null>}
     */
    async latest(scope, findingId) {
      return db.findingAiAdvisory.findFirst({
        where: where(scope, findingId),
        orderBy: { createdAt: "desc" },
        select: ADVISORY_COLUMNS,
      });
    },

    /**
     * The latest advisory per finding for a page of findings (list hints), keyed by finding id.
     * @type {(scope: import("./transitions.js").FindingScope, findingIds: string[]) => Promise<Map<string, object>>}
     */
    async latestFor(scope, findingIds) {
      const out = new Map();
      if (findingIds.length === 0) return out;
      const rows = await db.findingAiAdvisory.findMany({
        where: {
          tenantId: scope.tenantId,
          workspaceId: scope.workspaceId,
          findingId: { in: findingIds },
        },
        orderBy: { createdAt: "desc" },
        select: ADVISORY_COLUMNS,
      });
      for (const row of rows) if (!out.has(row.findingId)) out.set(row.findingId, row);
      return out;
    },

    /**
     * Whether a manual request is within the per-finding (3) and per-user (30) hourly limits.
     * @type {(scope: import("./transitions.js").FindingScope, findingId: string, userId: string, now: Date, tx?: any) => Promise<boolean>}
     */
    async requestAllowed(scope, findingId, userId, now, tx) {
      const n = await countManual(tx ?? db, scope, findingId, userId, now);
      return (
        n.perFinding < FINDINGS_LIMITS.advisoryRequestPerFindingPerHour &&
        n.perUser < FINDINGS_LIMITS.advisoryRequestPerUserPerHour
      );
    },

    /** Runs `fn(tx)` in one transaction (the manual request, its outbox row and its audit entry commit together). @type {<T>(fn: (tx: any) => Promise<T>) => Promise<T>} */
    transaction: (fn) => db.$transaction(fn),

    /**
     * Status of the workspace (`active`, `archived` or null when unknown), by tenant and id: an archived workspace refuses every mutation,
     * the manual advisory request included (D-F1, fixed 2026-11-24).
     * @type {(tx: any, scope: { tenantId: string, workspaceId: string }) => Promise<string | null>}
     */
    async workspaceStatus(tx, scope) {
      const w = await tx.workspace.findFirst({
        where: { tenantId: scope.tenantId, id: scope.workspaceId },
        select: { status: true },
      });
      return w?.status ?? null;
    },

    /**
     * Inside the caller's transaction: serialises manual requests for the finding (so the hourly limits cannot be raced), loads the
     * finding by TENANT, WORKSPACE and id, and checks that the agent runs on it. Returns `{ finding, applicable }`; a finding of
     * another tenant or workspace throws `FindingNotFoundError` (the identical 404).
     * @type {(tx: any, scope: import("./transitions.js").FindingScope, findingId: string) => Promise<{ finding: { id: string, workspaceId: string, repositoryId: string, pipelineId: string, scanType: string, severity: string }, applicable: boolean }>}
     */
    async lockForRequest(tx, scope, findingId) {
      await tx.$executeRaw`SELECT pg_advisory_xact_lock(hashtext(${`findings-advisory:${scope.tenantId}:${findingId}`}))`;
      const finding = await tx.finding.findFirst({
        where: { tenantId: scope.tenantId, workspaceId: scope.workspaceId, id: findingId },
        select: {
          id: true,
          workspaceId: true,
          repositoryId: true,
          pipelineId: true,
          scanType: true,
          severity: true,
        },
      });
      if (!finding) throw new FindingNotFoundError();
      return { finding, applicable: agentRunsOn(finding) };
    },

    /**
     * Writes the `finding.advisory.requested` job (reason `manual`) to the outbox in the caller's transaction. The message carries ids
     * and the requesting user as its initiator only; the agent re-validates ownership from the database.
     * @type {(tx: any, input: { tenantId: string, finding: { id: string, workspaceId: string, repositoryId: string, pipelineId: string }, userId: string, correlationId?: string | null, now: Date }) => Promise<{ messageId: string }>}
     */
    async enqueueManual(tx, { tenantId, finding, userId, correlationId, now }) {
      const messageId = `finding-advisory-${finding.id}-m${now.getTime()}-${globalThis.crypto.randomUUID().slice(0, 8)}`;
      const message = buildFindingMessage({
        kind: "job",
        type: "finding.advisory.requested",
        messageId,
        tenantId,
        workspaceId: finding.workspaceId,
        repositoryId: finding.repositoryId,
        pipelineId: finding.pipelineId,
        correlationId,
        initiator: initiatorOf({ type: "user", userId }),
        payload: {
          findingId: finding.id,
          workspaceId: finding.workspaceId,
          repositoryId: finding.repositoryId,
          pipelineId: finding.pipelineId,
          reason: "manual",
        },
        now,
      });
      await enqueueFindingMessages(tx, [{ queue: FINDING_QUEUES.FINDINGS_AGENT, message }]);
      return { messageId };
    },
  });
}
