import { Prisma } from "@prisma/client";
import { NO_APPLICABLE_SCANS_REASON } from "@qmentisai/shared";
import { withTransaction } from "../transaction.js";
import { LeaseLostError } from "./errors.js";
import { createExecutionRepository } from "./repository.js";

const DECISION_COLUMNS = Object.freeze({
  id: true,
  tenantId: true,
  workspaceId: true,
  repositoryId: true,
  pipelineId: true,
  executionId: true,
  scanKind: true,
  trust: true,
  diffSource: true,
  diffStatus: true,
  changedTotal: true,
  changeSummary: true,
  secretsRule: true,
  floor: true,
  agentStatus: true,
  agentProvider: true,
  agentModel: true,
  agentAdditions: true,
  agentSummary: true,
  agentUsage: true,
  finalTypes: true,
  notSelected: true,
  decidedAt: true,
});

const USAGE_KEYS = Object.freeze(["inputTokens", "outputTokens", "latencyMs", "turns"]);
const count = (value) => (Number.isInteger(value) && value >= 0 ? value : 0);
/** The stored usage object: the four counters only, or null when no model call was made. */
const usageOf = (usage) =>
  usage && typeof usage === "object"
    ? Object.fromEntries(USAGE_KEYS.map((key) => [key, count(usage[key])]))
    : null;

/**
 * Data access of the scan decision of an execution (docs/modules/scan-decisioning/SPEC.md 5.1, 5.6, 5.7, 7.2, 7.3). Same rules as
 * the other execution helpers: EVERYTHING is scoped by the trusted `tenantId`; the parent chain (workspace, repository, pipeline) is
 * validated against the stored row when it is given; the clock is the database's; every write of the lease holder is fenced by the
 * held `leaseEpoch` and runs inside the CALLER's transaction, so the decision, its events, the decided tasks and the transition to
 * `running` are one unit (SPEC 5.1). The database backs this up: the table is insert-once and its guard trigger refuses a decision
 * that is not exactly floor + additions inside the snapshot's enabled types.
 * @param {{ db: any }} deps Prisma client
 */
export function createScanDecisionRepository({ db }) {
  const executions = createExecutionRepository({ db });
  const requireTransaction = (tx, fn) => {
    if (typeof tx?.$transaction === "function")
      throw new TypeError(`${fn} must run inside the caller's transaction`);
  };

  return Object.freeze({
    /**
     * The decision of one execution, or null. Scoped by tenant and execution; when `workspaceId`, `repositoryId` or `pipelineId`
     * are given they must match the stored chain (a wrong parent finds nothing).
     * @param {{ tenantId: string, executionId: string, workspaceId?: string, repositoryId?: string, pipelineId?: string }} input
     * @param {any} [client]
     */
    findDecision: async (
      { tenantId, executionId, workspaceId, repositoryId, pipelineId },
      client = db,
    ) =>
      client.scanDecision.findFirst({
        where: {
          tenantId,
          executionId,
          ...(workspaceId ? { workspaceId } : {}),
          ...(repositoryId ? { repositoryId } : {}),
          ...(pipelineId ? { pipelineId } : {}),
        },
        select: DECISION_COLUMNS,
      }),

    /**
     * Whether a previous holder wrote the `decision_started` marker for this execution (SPEC 5.7 case 2). Tenant and execution scoped.
     * @param {{ tenantId: string, executionId: string }} input
     * @param {any} [client]
     * @returns {Promise<boolean>}
     */
    hasDecisionStarted: async ({ tenantId, executionId }, client = db) =>
      Boolean(
        await client.executionEvent.findFirst({
          where: { tenantId, executionId, type: "decision_started" },
          select: { id: true },
        }),
      ),

    /**
     * Writes the `decision_started` marker (empty details) as the lease holder, BEFORE the diff and the model are contacted. Fenced:
     * a zombie writes nothing. At most one marker per execution: a second call is a no-op. Returns whether this call wrote it.
     * @param {{ tenantId: string, executionId: string, leaseEpoch: number, correlationId?: string }} input
     * @param {any} [client]
     * @returns {Promise<boolean>}
     */
    async markDecisionStarted({ tenantId, executionId, leaseEpoch, correlationId }, client = db) {
      return withTransaction(client, async (tx) => {
        await executions.fenceExecution({ tenantId, executionId, leaseEpoch }, tx);
        const existing = await tx.executionEvent.findFirst({
          where: { tenantId, executionId, type: "decision_started" },
          select: { id: true },
        });
        if (existing) return false;
        const event = await executions.recordEvent(
          {
            tenantId,
            executionId,
            type: "decision_started",
            leaseEpoch,
            correlationId,
            details: {},
          },
          tx,
        );
        return Boolean(event);
      });
    },

    /**
     * Inserts the decision of an execution ONCE, inside the caller's transaction, fenced by the lease. The workspace, repository,
     * pipeline, scan kind and trust are read from the execution row (never from the caller). The database refuses a second row, a
     * row for an execution that is not preparing, a floor type missing from the final set, an addition inside the floor and a type
     * the snapshot did not enable.
     * @param {{ tenantId: string, executionId: string, leaseEpoch: number, decision: {
     *   diff: { source: string, status: string, changedTotal: number, summary: object },
     *   secretsRule: string,
     *   floor: Array<{ scanType: string, ruleIds: string[] }>,
     *   agent: { status: string, provider: string | null, model: string | null, additions: Array<{ scanType: string, reason: string }>, summary: string | null, usage: object | null },
     *   finalTypes: string[],
     *   notSelected: Array<{ scanType: string, reason: string }>,
     * } }} input
     * @param {any} tx The caller's TRANSACTION client.
     * @returns {Promise<{ id: string }>}
     */
    async insertDecision({ tenantId, executionId, leaseEpoch, decision }, tx) {
      requireTransaction(tx, "insertDecision");
      await executions.fenceExecution({ tenantId, executionId, leaseEpoch }, tx);
      const exec = await tx.execution.findFirst({
        where: { id: executionId, tenantId },
        select: {
          workspaceId: true,
          repositoryId: true,
          pipelineId: true,
          scanKind: true,
          trust: true,
        },
      });
      if (!exec) throw new LeaseLostError({ executionId, leaseEpoch });
      const { diff, agent } = decision;
      return tx.scanDecision.create({
        data: {
          tenantId,
          workspaceId: exec.workspaceId,
          repositoryId: exec.repositoryId,
          pipelineId: exec.pipelineId,
          executionId,
          scanKind: exec.scanKind,
          trust: exec.trust,
          diffSource: diff.source,
          diffStatus: diff.status,
          changedTotal: diff.status === "complete" ? count(diff.changedTotal) : 0,
          changeSummary: diff.summary ?? {},
          secretsRule: decision.secretsRule,
          floor: decision.floor.map((f) => ({ scanType: f.scanType, ruleIds: [...f.ruleIds] })),
          agentStatus: agent.status,
          agentProvider: agent.provider ?? null,
          agentModel: agent.model ?? null,
          agentAdditions: agent.additions.map((a) => ({ scanType: a.scanType, reason: a.reason })),
          agentSummary: agent.summary ? agent.summary : null,
          agentUsage: usageOf(agent.usage) ?? Prisma.DbNull,
          finalTypes: [...decision.finalTypes],
          notSelected: decision.notSelected.map((n) => ({
            scanType: n.scanType,
            reason: n.reason,
          })),
        },
        select: { id: true },
      });
    },

    /**
     * Records the `decision_completed` event (the bounded facts of the decision: floor, added, final, agent status, provider, model,
     * a short summary, diff status, changed total; no prompt, no file contents), fenced, inside the caller's transaction.
     * @param {{ tenantId: string, executionId: string, leaseEpoch: number, correlationId?: string, details: Record<string, unknown> }} input
     * @param {any} tx The caller's TRANSACTION client.
     */
    async recordDecisionCompleted(
      { tenantId, executionId, leaseEpoch, correlationId, details },
      tx,
    ) {
      requireTransaction(tx, "recordDecisionCompleted");
      const event = await executions.recordEvent(
        {
          tenantId,
          executionId,
          type: "decision_completed",
          leaseEpoch,
          correlationId,
          details,
        },
        tx,
      );
      if (!event) throw new LeaseLostError({ executionId, leaseEpoch });
      return event;
    },

    /**
     * The zero-scan ending (SPEC 5.6, AP-3), inside the caller's transaction and fenced: `preparing -> running -> succeeded` with
     * the same lease epoch (two transition events), reason `no_applicable_scans`, zero task counts and the quota unit given back
     * EXACTLY once (compare-and-set plus `quota_released_at`). Refuses when the execution has any scan task or its decision does
     * not have an empty final set (the database trigger refuses the same). A lost fence rolls the caller's transaction back.
     * @param {{ tenantId: string, executionId: string, leaseEpoch: number, correlationId?: string, startedDetails?: Record<string, unknown>, endedDetails?: Record<string, unknown> }} input
     * @param {any} tx The caller's TRANSACTION client.
     * @returns {Promise<{ started: { statusRev: number }, ended: { statusRev: number }, quotaReleased: boolean }>}
     */
    async finishZeroScan(
      { tenantId, executionId, leaseEpoch, correlationId, startedDetails = {}, endedDetails = {} },
      tx,
    ) {
      requireTransaction(tx, "finishZeroScan");
      await executions.fenceExecution({ tenantId, executionId, leaseEpoch }, tx);
      if ((await tx.scanTask.count({ where: { tenantId, executionId } })) > 0)
        throw new Error("A zero-scan execution cannot have scan tasks.");
      const decision = await tx.scanDecision.findFirst({
        where: { tenantId, executionId },
        select: { finalTypes: true },
      });
      if (!decision || !Array.isArray(decision.finalTypes) || decision.finalTypes.length !== 0)
        throw new Error("The zero-scan ending needs a recorded decision with an empty final set.");
      const started = await executions.transitionExecution(
        {
          tenantId,
          executionId,
          from: "preparing",
          to: "running",
          leaseEpoch,
          actor: { type: "system" },
          correlationId,
          eventDetails: { epoch: leaseEpoch, taskCount: 0, ...startedDetails },
        },
        tx,
      );
      if (!started.transitioned) throw new LeaseLostError({ executionId, leaseEpoch });
      const ended = await executions.transitionExecution(
        {
          tenantId,
          executionId,
          from: "running",
          to: "succeeded",
          reason: NO_APPLICABLE_SCANS_REASON,
          leaseEpoch,
          releaseQuota: true,
          taskCounts: {
            total: 0,
            succeeded: 0,
            failed: 0,
            timed_out: 0,
            cancelled: 0,
            skipped: 0,
            unsupported: 0,
          },
          actor: { type: "system" },
          correlationId,
          eventDetails: { epoch: leaseEpoch, ...endedDetails },
        },
        tx,
      );
      if (!ended.transitioned) throw new LeaseLostError({ executionId, leaseEpoch });
      return {
        started: { statusRev: started.execution.statusRev },
        ended: { statusRev: ended.execution.statusRev },
        quotaReleased: ended.quotaReleased,
      };
    },
  });
}
