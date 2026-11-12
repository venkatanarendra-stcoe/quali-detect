import { createHash } from "node:crypto";
import { QUEUE_NAMES, createEventEnvelope } from "@qmentisai/contracts";
import {
  EntitlementError,
  QUOTA_KEYS,
  createEntitlementRepository,
  createEntitlementService,
  createOutboxRepository,
  withTransaction,
} from "@qmentisai/db";
import { NonRetryableError, TransientError, createOutbox } from "@qmentisai/infra";
import {
  TRIGGER_DECISION_REASONS,
  USABLE_TENANT_STATUSES,
  canonicalJson,
  computeEffectiveState,
  createPipelineConfigSchema,
  evaluatePipelineTriggers,
  evaluateTrigger,
  scanRelevantPart,
} from "@qmentisai/shared";
import { auditSystem } from "../scm/audit.js";
import { createRouterRepository } from "./repository.js";

/** Audit action names (the same strings as the API's `AUDIT_ACTIONS`; a worker cannot import `apps/api`). */
const AUDIT = Object.freeze({
  BLOCKED: "execution.blocked",
  SKIPPED: "execution.skipped",
  CANCELLED_SUPERSEDED: "execution.cancelled_superseded",
});

/** Statuses that make a request "in flight" for the `skip` concurrency policy (SPEC §5.8). */
const IN_FLIGHT = Object.freeze(["queued", "preparing", "running", "cancelling"]);

/**
 * The configuration is validated AGAIN here (SPEC §5.7.1, PIPE-015). The limits are deliberately wide: the API applied the
 * platform limits when the version was published, and a stored version must stay readable if a limit is lowered later; what
 * matters here is the shape (strict, no unknown keys, supported schema version).
 */
const CONFIG_SCHEMA = createPipelineConfigSchema({
  timeoutMinSeconds: 1,
  timeoutMaxSeconds: 31536000,
  timeoutDefaultSeconds: 1800,
  scanTaskTimeoutMinSeconds: 1,
  maxQueuedPerPipeline: 100000,
  scheduleMinIntervalSeconds: 1,
  maxSchedulesPerPipeline: 1000,
  maxPatternsPerList: 1000,
  maxPatternLength: 512,
  maxExclusionPaths: 10000,
  maxActiveLimit: 1000,
});

const SHA = /^([0-9a-f]{40}|[0-9a-f]{64})$/;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
/** A commit id as stored (lower-case hex of the right length) or null: the database CHECK refuses anything else. */
const shaOf = (value) =>
  typeof value === "string" && SHA.test(value.toLowerCase()) ? value.toLowerCase() : null;
const sha256 = (value) => createHash("sha256").update(value).digest("hex");
const cap = (value, max) => (value.length > max ? value.slice(0, max) : value);

/** Signal that the quota/entitlement gate refused a request: rolls the creating transaction back, then a `blocked` row is written. */
class QuotaBlocked extends Error {
  constructor(reason, base) {
    super(reason);
    this.reason = reason;
    this.base = base;
  }
}

/**
 * The pipeline trigger router (docs/modules/pipelines-triggers/SPEC.md §6.2): the handler of queue `pipeline-triggers`
 * (bound to `scm.github.push` and `scm.github.pull_request` on the SCM events exchange). For one `scm.push.received` /
 * `scm.pull_request.received` message it loads the repository's pipelines, evaluates their triggers with the shared pure
 * evaluator and creates one `queued` execution request per matching pipeline, each in its OWN database transaction.
 *
 * Fail-closed order: (the consumer already validated the envelope, the tenant, the workspace and the repository's tenant) ->
 * repository, workspace and tenant state from the database -> the normalized `scm_events` row -> candidate pipelines of this
 * tenant, workspace and repository -> match -> per pipeline: policy skip (decision row), quota/entitlement block (`blocked` row
 * + audit entry), or a request (execution + quota + outbox message in one transaction).
 *
 * Idempotency: the `(tenant, pipeline, scm event)` unique key and an advisory lock per pipeline. A duplicate is "already
 * handled", not an error, so a redelivery after a crash between two pipelines only creates what is missing. Unexpected
 * failures of one pipeline never stop the others; they are retried afterwards as a transient error for the whole message.
 * @param {{ db: any, config?: { pipelines?: { maxPerRepository?: number } }, logger?: any, clock?: () => Date }} deps
 */
export function createPipelineTriggerHandler({ db, config, logger, clock = () => new Date() }) {
  const repo = createRouterRepository({ db });
  const entitlements = createEntitlementService({
    repository: createEntitlementRepository({ db }),
  });
  const outbox = createOutbox({ repository: createOutboxRepository({ db }) });
  const maxPerRepository = config?.pipelines?.maxPerRepository ?? 20;

  /** What the evaluator and the execution row need from the message (payload fields only; ids, enums, short strings). */
  function describe(message) {
    const p = message.payload;
    if (message.type === "scm.push.received")
      return {
        kind: "push",
        event: {
          kind: "push",
          ref: p.ref,
          branch: p.branch,
          created: p.created,
          deleted: p.deleted,
          forced: p.forced,
        },
        commitSha: shaOf(p.headCommitSha) ?? shaOf(p.after),
        baseSha: shaOf(p.before),
        baseRef: null,
        pullRequestNumber: null,
      };
    if (message.type === "scm.pull_request.received") {
      if (!Number.isInteger(p.number) || p.number < 1)
        throw new NonRetryableError("The pull request number is not valid.", {
          reason: "invalid-payload",
        });
      return {
        kind: "pull_request",
        event: {
          kind: "pull_request",
          action: p.action,
          number: p.number,
          baseRef: p.baseRef,
          headRef: p.headRef,
          // unknown is already mapped to true by the producer; anything but an explicit false is still a fork here
          isFork: p.isFork !== false,
          draft: p.draft,
          merged: p.merged,
        },
        commitSha: shaOf(p.headSha),
        baseSha: shaOf(p.baseSha),
        baseRef: p.baseRef ? cap(p.baseRef, 255) : null,
        pullRequestNumber: p.number,
      };
    }
    throw new NonRetryableError(`The trigger router does not handle "${message.type}".`, {
      reason: "unsupported-message-type",
    });
  }

  /** Writes a `skipped` request (concurrency skip, queue full, stale event) and its audit entry. */
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

  /** The fields every execution row of this event shares. */
  function baseRow(ctx, version, final) {
    const refName = cap(final.refName, 255);
    const group = final.concurrencyGroup;
    return {
      tenantId: ctx.tenantId,
      workspaceId: ctx.workspaceId,
      repositoryId: ctx.repositoryId,
      pipelineId: ctx.pipeline.id,
      configVersionId: version.id,
      configVersion: version.version,
      configHash: version.configHash,
      triggerType: ctx.kind,
      triggerKey: final.triggerKey,
      scmEventId: ctx.scmEventId,
      scmDeliveryId: ctx.deliveryId,
      scmEventKind: ctx.kind,
      refType: final.refType,
      refName,
      baseRef: ctx.baseRef,
      pullRequestNumber: ctx.pullRequestNumber,
      commitSha: ctx.commitSha,
      baseSha: ctx.baseSha,
      scanKind: final.scanKind,
      scanKindReason: final.scanKindReason,
      trust: final.trust,
      // the database refuses groups longer than 300 characters; a ref can be 512
      concurrencyGroup: group.length > 300 ? `${group.slice(0, 4)}${sha256(group)}` : group,
      idempotencyKey: `scm:${ctx.deliveryId}:${ctx.kind}`,
      correlationId: ctx.correlationId,
    };
  }

  /** Everything of ONE request inside the caller's transaction (SPEC §6.2 step 8). Throws `QuotaBlocked` to roll back. */
  async function requestInTransaction(tx, ctx, version, cfg, evaluation) {
    await repo.lockPipeline({ tenantId: ctx.tenantId, pipelineId: ctx.pipeline.id }, tx);
    const existing = await repo.findExecutionByScmEvent(
      { tenantId: ctx.tenantId, pipelineId: ctx.pipeline.id, scmEventId: ctx.scmEventId },
      tx,
    );
    if (existing) return { outcome: "duplicate" };

    // History for the requested scan kind (SPEC §5.7): the first request, or a changed scan-relevant configuration, is full.
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
    const trigger = cfg.triggers.find((t) => t.key === evaluation.triggerKey);
    const final = {
      ...evaluateTrigger({
        trigger,
        event: ctx.event,
        repository: { defaultBranch: ctx.defaultBranch },
        effectiveState: ctx.state,
        scanMode: cfg.scanMode,
        history: { isFirstRequest: !latest, configChanged },
      }),
      triggerKey: evaluation.triggerKey,
    };
    if (final.decision !== "match") return { outcome: "no_match" };
    const base = baseRow(ctx, version, final);

    let supersededCount = 0;
    // Concurrency policy (SPEC §5.8-5.9b), applied under the pipeline lock, exactly as the manual run does.
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
        initiator: { type: "scm", id: "github-webhook" },
        subject: { type: "execution", id: row.id },
        payload: {
          executionId: row.id,
          pipelineId: ctx.pipeline.id,
          repositoryId: ctx.repositoryId,
          workspaceId: ctx.workspaceId,
          configVersion: version.version,
          configHash: version.configHash,
          triggerType: ctx.kind,
          triggerKey: final.triggerKey,
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

  /** Quota or entitlement refused: the `blocked` row, and ONE audit entry per pipeline, reason and UTC day (SPEC §5.9b). */
  async function recordBlocked(ctx, blocked) {
    return withTransaction(db, async (tx) => {
      await repo.lockPipeline({ tenantId: ctx.tenantId, pipelineId: ctx.pipeline.id }, tx);
      const existing = await repo.findExecutionByScmEvent(
        { tenantId: ctx.tenantId, pipelineId: ctx.pipeline.id, scmEventId: ctx.scmEventId },
        tx,
      );
      if (existing) return { outcome: "duplicate" };
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
    });
  }

  /** One pipeline's request: its own transaction; a duplicate key is "already handled". */
  async function request(ctx, version, cfg, evaluation) {
    try {
      return await withTransaction(db, (tx) =>
        requestInTransaction(tx, ctx, version, cfg, evaluation),
      );
    } catch (error) {
      if (error instanceof QuotaBlocked) {
        try {
          return await recordBlocked(ctx, error);
        } catch (inner) {
          if (inner?.code === "P2002") return { outcome: "duplicate" };
          throw inner;
        }
      }
      // the unique `(tenant, pipeline, scm event)` / idempotency key is the backstop of the advisory lock
      if (error?.code === "P2002") return { outcome: "duplicate" };
      throw error;
    }
  }

  /** A policy skip: one decision row per pipeline, delivery and trigger (a redelivery adds nothing). */
  async function recordDecision(ctx, evaluation) {
    const reason = evaluation.reasons[0];
    if (!TRIGGER_DECISION_REASONS.includes(reason))
      return { outcome: "policy_skip_unrecorded", reason };
    await repo.createDecision({
      tenantId: ctx.tenantId,
      workspaceId: ctx.workspaceId,
      repositoryId: ctx.repositoryId,
      pipelineId: ctx.pipeline.id,
      triggerType: ctx.kind,
      triggerKey: evaluation.triggerKey,
      scmEventId: ctx.scmEventId,
      scmDeliveryId: ctx.deliveryId,
      scmEventKind: ctx.kind,
      reason,
      refType: evaluation.refType,
      refName: cap(evaluation.refName, 255),
      pullRequestNumber: ctx.pullRequestNumber,
      correlationId: ctx.correlationId,
    });
    return { outcome: "policy_skip", reason };
  }

  return async function handlePipelineTrigger(message, { log = logger } = {}) {
    const { tenantId } = message;
    const described = describe(message);
    const { payload } = message;

    // Ownership, again from the database: the repository must belong to the tenant of the message; its workspace is the
    // authority for the workspace (a mismatching envelope workspace is a forged message).
    const repository = await repo.findRepositoryState({ tenantId, id: payload.repositoryId });
    if (!repository)
      throw new NonRetryableError("The repository does not belong to the tenant.", {
        reason: "resource-not-in-tenant",
      });
    if (message.workspaceId && message.workspaceId !== repository.workspaceId)
      throw new NonRetryableError("The workspace does not match the repository.", {
        reason: "resource-not-in-tenant",
      });
    if (!USABLE_TENANT_STATUSES.includes(repository.tenant.status))
      throw new NonRetryableError("The tenant does not exist or is not active.", {
        reason: "tenant-not-usable",
      });
    const scmEvent = await repo.findScmEvent({
      tenantId,
      deliveryId: payload.deliveryId,
      kind: described.kind,
    });
    if (!scmEvent)
      throw new NonRetryableError("The normalized SCM event is not stored.", {
        reason: "scm-event-missing",
      });
    if (scmEvent.repositoryId !== repository.id)
      throw new NonRetryableError("The SCM event belongs to another repository.", {
        reason: "resource-not-in-tenant",
      });

    const pipelines = await repo.listRoutingPipelines({
      tenantId,
      workspaceId: repository.workspaceId,
      repositoryId: repository.id,
      limit: maxPerRepository,
    });

    const ctx = {
      tenantId,
      workspaceId: repository.workspaceId,
      repositoryId: repository.id,
      defaultBranch: repository.defaultBranch,
      kind: described.kind,
      event: described.event,
      commitSha: described.commitSha,
      baseSha: described.baseSha,
      baseRef: described.baseRef,
      pullRequestNumber: described.pullRequestNumber,
      scmEventId: scmEvent.id,
      deliveryId: payload.deliveryId,
      messageId: message.messageId,
      correlationId: message.correlationId,
      auditCorrelationId: UUID.test(message.correlationId ?? "") ? message.correlationId : null,
    };

    const counts = {};
    const bump = (key) => {
      counts[key] = (counts[key] ?? 0) + 1;
    };
    const poison = [];
    const failures = [];
    for (const pipeline of pipelines) {
      const pctx = { ...ctx, pipeline };
      try {
        const version = pipeline.currentConfig;
        if (!version) {
          bump("no_version");
          continue;
        }
        if (version.schemaVersion !== 1) {
          poison.push({ pipelineId: pipeline.id, problem: "unsupported-schema-version" });
          continue;
        }
        const parsed = CONFIG_SCHEMA.safeParse(version.config);
        if (!parsed.success) {
          poison.push({ pipelineId: pipeline.id, problem: "invalid-config" });
          continue;
        }
        const cfg = parsed.data;
        const state = computeEffectiveState({
          tenantStatus: repository.tenant.status,
          workspaceStatus: repository.workspace.status,
          repositoryStatus: repository.status,
          repositoryEnabled: repository.enabled,
          pipelineEnabled: pipeline.enabled,
        });
        pctx.state = state;
        const evaluations = evaluatePipelineTriggers({
          config: cfg,
          event: described.event,
          repository: { defaultBranch: repository.defaultBranch },
          effectiveState: state,
        });
        const matched = evaluations.filter((e) => e.decision !== "no_match");
        if (matched.length === 0) {
          bump("no_match");
          continue;
        }
        // At most one trigger per type exists, so at most one match per pipeline; the unique key makes a second one a duplicate.
        for (const evaluation of matched) {
          const result =
            evaluation.decision === "policy_skip"
              ? await recordDecision(pctx, evaluation)
              : await request(pctx, version, cfg, evaluation);
          bump(result.outcome);
          log?.info?.(
            {
              metric: "pipeline_trigger_decisions_total",
              type: ctx.kind,
              decision: result.outcome,
              reason: result.reason ?? evaluation.reasons[0],
              pipelineId: pipeline.id,
              executionId: result.executionId,
            },
            "Pipeline trigger outcome",
          );
        }
      } catch (error) {
        if (error instanceof NonRetryableError)
          poison.push({ pipelineId: pipeline.id, problem: error.reason });
        else failures.push({ pipelineId: pipeline.id, error });
      }
    }

    log?.info?.(
      {
        messageId: message.messageId,
        deliveryId: payload.deliveryId,
        tenantId,
        repositoryId: repository.id,
        pipelinesEvaluated: pipelines.length,
        executionsCreated: counts.created ?? 0,
        outcomes: counts,
      },
      "Pipeline trigger message routed",
    );
    // One pipeline's trouble never blocks the others (they ran above). Transient trouble retries the WHOLE message safely
    // (the unique keys absorb what already exists); an unreadable configuration is a poison message.
    if (failures.length > 0)
      throw new TransientError(
        `Routing failed for ${failures.length} pipeline(s); the message is retried.`,
        { cause: failures[0].error },
      );
    if (poison.length > 0)
      throw new NonRetryableError(
        `A pipeline configuration cannot be used (${poison.map((p) => p.problem).join(", ")}).`,
        { reason: "invalid-pipeline-config" },
      );
  };
}
