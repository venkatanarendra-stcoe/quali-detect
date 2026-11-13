import { createHash } from "node:crypto";
import { QUEUE_NAMES, createEventEnvelope } from "@qmentisai/contracts";
import {
  EntitlementError,
  QUOTA_KEYS,
  createEntitlementRepository,
  createEntitlementService,
  createOutboxRepository,
} from "@qmentisai/db";
import { createOutbox } from "@qmentisai/infra";
import { canonicalJson, createPipelineConfigSchema, scanRelevantPart } from "@qmentisai/shared";
import { auditSystem } from "../scm/audit.js";
import { createRouterRepository } from "./repository.js";

/**
 * The creation of ONE execution request, shared by every unattended producer of requests: the SCM trigger router
 * (`router.js`) and the schedule handler (`../scheduler/schedules.js`). Both produce the same shape of rows, audit entries and
 * `pipeline.execution.requested` messages (docs/modules/pipelines-triggers/SPEC.md §6.2 step 8, §6.4), so the concurrency
 * policy, the quota consumption, the `blocked` / `skipped` rows and the outbox message live here once. Every function takes
 * the caller's transaction client; nothing here opens a transaction, so the caller decides what is atomic with the request.
 */

/** Audit action names (the same strings as the API's `AUDIT_ACTIONS`; a worker cannot import `apps/api`). */
export const AUDIT = Object.freeze({
  BLOCKED: "execution.blocked",
  SKIPPED: "execution.skipped",
  CANCELLED_SUPERSEDED: "execution.cancelled_superseded",
  CANCELLED_PR_CLOSED: "execution.cancelled_pr_closed",
});

/** Statuses that make a request "in flight" for the `skip` concurrency policy (SPEC §5.8). */
const IN_FLIGHT = Object.freeze(["queued", "preparing", "running", "cancelling"]);

/**
 * The configuration is validated AGAIN by every worker that reads it (SPEC §5.7.1, PIPE-015). The limits are deliberately
 * wide: the API applied the platform limits when the version was published, and a stored version must stay readable if a
 * limit is lowered later; what matters here is the shape (strict, no unknown keys, supported schema version). A minimum
 * interval of 0 validates the schedule syntax only (the real evaluation belongs to publishing, not to every message).
 */
export const CONFIG_SCHEMA = createPipelineConfigSchema({
  timeoutMinSeconds: 1,
  timeoutMaxSeconds: 31536000,
  timeoutDefaultSeconds: 1800,
  scanTaskTimeoutMinSeconds: 1,
  maxQueuedPerPipeline: 100000,
  scheduleMinIntervalSeconds: 0,
  maxSchedulesPerPipeline: 1000,
  maxPatternsPerList: 1000,
  maxPatternLength: 512,
  maxExclusionPaths: 10000,
  maxActiveLimit: 1000,
});

export const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const sha256 = (value) => createHash("sha256").update(value).digest("hex");
/** Truncates text to `max` characters. @param {string} value @param {number} max */
export const cap = (value, max) => (value.length > max ? value.slice(0, max) : value);

/** The concurrency group as stored: the database refuses more than 300 characters, a ref can be 512. @param {string} group */
export const storedGroup = (group) =>
  group.length > 300 ? `${group.slice(0, 4)}${sha256(group)}` : group;

/** Signal that the quota/entitlement gate refused a request: the caller rolls the creating work back, then records a `blocked` row. */
export class QuotaBlocked extends Error {
  constructor(reason, base) {
    super(reason);
    this.reason = reason;
    this.base = base;
  }
}

/**
 * The request writer. `ctx` carries: `tenantId`, `workspaceId`, `repositoryId`, `pipeline` (`{ id }`), `kind` (the trigger
 * type: push, pull_request or schedule), `correlationId`, `auditCorrelationId` (a UUID or null), `messageId` (the causing
 * message), `initiator` (`{ type, id }` of the envelope), `commitSha` (null for schedules).
 * @param {{ db: any, clock?: () => Date }} deps
 */
export function createExecutionRequestWriter({ db, clock = () => new Date() }) {
  const repo = createRouterRepository({ db });
  const entitlements = createEntitlementService({
    repository: createEntitlementRepository({ db }),
  });
  const outbox = createOutbox({ repository: createOutboxRepository({ db }) });

  /** Writes a `skipped` request (concurrency skip, queue full, stale event, missed run) and its audit entry. */
  async function skipped(tx, ctx, base, reason) {
    const row = await repo.createExecution(
      { ...base, status: "skipped", statusReason: reason },
      tx,
    );
    await auditSystem(tx, {
      tenantId: ctx.tenantId,
      action: AUDIT.SKIPPED,
      targetType: "pipeline",
      targetId: ctx.pipeline.id,
      workspaceId: ctx.workspaceId,
      correlationId: ctx.auditCorrelationId,
      metadata: {
        executionId: row.id,
        reason,
        triggerType: ctx.kind,
        refName: base.refName,
      },
    });
    return { outcome: "skipped", reason, executionId: row.id };
  }

  /**
   * History for the requested scan kind (SPEC §5.7): the first request, or a changed scan-relevant configuration, is full.
   * @returns {Promise<{ isFirstRequest: boolean, configChanged: boolean }>}
   */
  async function scanHistory(tx, ctx, cfg) {
    const latest = await repo.findLatestExecution(
      { tenantId: ctx.tenantId, pipelineId: ctx.pipeline.id },
      tx,
    );
    let configChanged = false;
    if (latest) {
      const previous = CONFIG_SCHEMA.safeParse(latest.version.config);
      configChanged =
        !previous.success ||
        canonicalJson(scanRelevantPart(previous.data)) !== canonicalJson(scanRelevantPart(cfg));
    }
    return { isFirstRequest: !latest, configChanged };
  }

  /**
   * Concurrency policy, quota, the `queued` row and the outbox message (SPEC §5.8, §6.2 steps 8b to 8d), all inside the
   * caller's transaction and under the caller's per-pipeline advisory lock. Throws `QuotaBlocked` when the quota or the
   * entitlement refuses: the caller rolls back (the policy's cancellations and the half-written work) and calls
   * `recordBlocked`.
   * @param {any} tx @param {any} ctx @param {any} base the execution row fields common to every status
   * @param {any} cfg the validated configuration @param {{ number: number, id: string, configHash: string }} version
   */
  async function createRequest(tx, ctx, base, cfg, version) {
    let supersededCount = 0;
    const policy = cfg.execution?.concurrency ?? {};
    if (policy.policy === "skip") {
      const busy = await repo.countExecutions(
        {
          tenantId: ctx.tenantId,
          pipelineId: ctx.pipeline.id,
          statuses: IN_FLIGHT,
          concurrencyGroup: base.concurrencyGroup,
        },
        tx,
      );
      if (busy > 0) return skipped(tx, ctx, base, "concurrency_skip");
    } else if (policy.policy === "queue") {
      const queued = await repo.countExecutions(
        { tenantId: ctx.tenantId, pipelineId: ctx.pipeline.id, statuses: ["queued"] },
        tx,
      );
      if (queued >= (policy.maxQueued ?? 0)) return skipped(tx, ctx, base, "queue_full");
    } else {
      // supersede: an event that arrives late (a later push already names its commit as base) is stale, never the newer one
      if (ctx.kind === "push" && ctx.commitSha) {
        const newer = await repo.findNewerInGroup(
          {
            tenantId: ctx.tenantId,
            pipelineId: ctx.pipeline.id,
            concurrencyGroup: base.concurrencyGroup,
            baseSha: ctx.commitSha,
          },
          tx,
        );
        if (newer) return skipped(tx, ctx, base, "stale_event");
      }
      const superseded = await repo.cancelQueued(
        {
          tenantId: ctx.tenantId,
          pipelineId: ctx.pipeline.id,
          concurrencyGroup: base.concurrencyGroup,
          reason: "superseded",
        },
        tx,
      );
      supersededCount = superseded.length;
      for (const row of superseded) {
        if (row.quotaConsumed > 0 && row.quotaPeriod)
          await entitlements.releaseQuota(
            {
              tenantId: ctx.tenantId,
              quotaKey: QUOTA_KEYS.SCANS_MONTHLY,
              amount: row.quotaConsumed,
              periodKey: row.quotaPeriod,
            },
            tx,
          );
        await auditSystem(tx, {
          tenantId: ctx.tenantId,
          action: AUDIT.CANCELLED_SUPERSEDED,
          targetType: "pipeline",
          targetId: ctx.pipeline.id,
          workspaceId: ctx.workspaceId,
          correlationId: ctx.auditCorrelationId,
          metadata: { executionId: row.id, triggerType: ctx.kind, refName: base.refName },
        });
      }
    }

    // Entitlement and quota in the same transaction: a crash can neither leak a unit nor create an unmetered request.
    const period = clock().toISOString().slice(0, 7);
    try {
      await entitlements.consumeQuota(
        {
          tenantId: ctx.tenantId,
          quotaKey: QUOTA_KEYS.SCANS_MONTHLY,
          amount: 1,
          periodKey: period,
        },
        tx,
      );
    } catch (error) {
      if (error instanceof EntitlementError)
        throw new QuotaBlocked(
          error.code === "ENTITLEMENT_REQUIRED" ? "entitlement_required" : "quota_exceeded",
          base,
        );
      throw error;
    }
    const row = await repo.createExecution(
      { ...base, status: "queued", quotaPeriod: period, quotaConsumed: 1 },
      tx,
    );
    await outbox.enqueue(tx, {
      queue: QUEUE_NAMES.PIPELINE,
      message: createEventEnvelope({
        messageId: `execution-requested-${row.id}`,
        type: "pipeline.execution.requested",
        schemaVersion: 1,
        tenantId: ctx.tenantId,
        workspaceId: ctx.workspaceId,
        repositoryId: ctx.repositoryId,
        pipelineId: ctx.pipeline.id,
        executionId: row.id,
        correlationId: ctx.correlationId,
        causationId: ctx.messageId,
        initiator: ctx.initiator,
        subject: { type: "execution", id: row.id },
        payload: {
          executionId: row.id,
          pipelineId: ctx.pipeline.id,
          repositoryId: ctx.repositoryId,
          workspaceId: ctx.workspaceId,
          configVersion: version.version,
          configHash: version.configHash,
          triggerType: ctx.kind,
          triggerKey: base.triggerKey,
          refType: row.refType,
          refName: row.refName,
          commitSha: row.commitSha,
          pullRequestNumber: row.pullRequestNumber,
          scanKind: row.scanKind,
          scanKindReason: row.scanKindReason,
          trust: row.trust,
        },
      }),
    });
    return {
      outcome: "created",
      executionId: row.id,
      scanKind: row.scanKind,
      trust: row.trust,
      superseded: supersededCount,
    };
  }

  /**
   * A pull request was closed (merged or not): cancels the pipeline's still-`queued` requests of THAT pull request (status
   * `cancelled`, reason `cancelled_pr_closed`), gives their quota back exactly once, audits each one and leaves ONE trigger
   * decision row (reason `cancelled_pr_closed`, keyed by the delivery, so a redelivery adds nothing). Nothing is written when
   * nothing was queued, which also makes a replay a no-op. Runs inside the caller's transaction and per-pipeline lock; the
   * running and the terminal requests are never touched. `ctx.pullRequestNumber` and `ctx.scmEventReceivedAt` come from the closed event.
   * @param {any} tx @param {any} ctx
   * @returns {Promise<{ outcome: "pr_closed_cancelled" | "pr_closed_nothing_queued", cancelled: number }>}
   */
  async function cancelClosedPullRequest(tx, ctx) {
    const reason = "cancelled_pr_closed";
    const cancelled = await repo.cancelQueuedForPullRequest(
      {
        tenantId: ctx.tenantId,
        workspaceId: ctx.workspaceId,
        repositoryId: ctx.repositoryId,
        pipelineId: ctx.pipeline.id,
        pullRequestNumber: ctx.pullRequestNumber,
        receivedUntil: ctx.scmEventReceivedAt,
        reason,
      },
      tx,
    );
    if (cancelled.length === 0) return { outcome: "pr_closed_nothing_queued", cancelled: 0 };
    for (const row of cancelled) {
      if (row.quotaConsumed > 0 && row.quotaPeriod)
        await entitlements.releaseQuota(
          {
            tenantId: ctx.tenantId,
            quotaKey: QUOTA_KEYS.SCANS_MONTHLY,
            amount: row.quotaConsumed,
            periodKey: row.quotaPeriod,
          },
          tx,
        );
      await auditSystem(tx, {
        tenantId: ctx.tenantId,
        action: AUDIT.CANCELLED_PR_CLOSED,
        targetType: "pipeline",
        targetId: ctx.pipeline.id,
        workspaceId: ctx.workspaceId,
        correlationId: ctx.auditCorrelationId,
        metadata: {
          executionId: row.id,
          triggerType: "pull_request",
          refName: `pull/${ctx.pullRequestNumber}`,
        },
      });
    }
    await repo.createDecision(
      {
        tenantId: ctx.tenantId,
        workspaceId: ctx.workspaceId,
        repositoryId: ctx.repositoryId,
        pipelineId: ctx.pipeline.id,
        triggerType: "pull_request",
        triggerKey: cancelled[0].triggerKey,
        sourceType: "scm_event",
        scmEventId: ctx.scmEventId,
        scmDeliveryId: ctx.deliveryId,
        scmEventKind: "pull_request",
        reason,
        refType: "pull_request",
        refName: `pull/${ctx.pullRequestNumber}`,
        pullRequestNumber: ctx.pullRequestNumber,
        correlationId: ctx.correlationId,
      },
      tx,
    );
    return { outcome: "pr_closed_cancelled", cancelled: cancelled.length };
  }

  /**
   * Quota or entitlement refused: the `blocked` row, and ONE audit entry per pipeline, reason and UTC day (SPEC §5.9b).
   * `findExisting` answers whether the request of this event or slot already has a row (a duplicate).
   * @param {any} tx @param {any} ctx @param {QuotaBlocked} blocked @param {(tx: any) => Promise<unknown>} findExisting
   */
  async function recordBlocked(tx, ctx, blocked, findExisting) {
    if (await findExisting(tx)) return { outcome: "duplicate" };
    const row = await repo.createExecution(
      { ...blocked.base, status: "blocked", statusReason: blocked.reason },
      tx,
    );
    const now = clock();
    const since = new Date(Date.UTC(now.getUTCFullYear(), now.getUTCMonth(), now.getUTCDate()));
    const audited = await repo.hasBlockedAuditSince(
      {
        tenantId: ctx.tenantId,
        pipelineId: ctx.pipeline.id,
        action: AUDIT.BLOCKED,
        reason: blocked.reason,
        since,
      },
      tx,
    );
    if (!audited)
      await auditSystem(tx, {
        tenantId: ctx.tenantId,
        action: AUDIT.BLOCKED,
        targetType: "pipeline",
        targetId: ctx.pipeline.id,
        workspaceId: ctx.workspaceId,
        correlationId: ctx.auditCorrelationId,
        metadata: {
          executionId: row.id,
          reason: blocked.reason,
          triggerType: ctx.kind,
          refName: blocked.base.refName,
        },
      });
    return { outcome: "blocked", reason: blocked.reason, executionId: row.id };
  }

  return Object.freeze({
    skipped,
    scanHistory,
    createRequest,
    recordBlocked,
    cancelClosedPullRequest,
  });
}
