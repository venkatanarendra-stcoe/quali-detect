import { withTransaction } from "@qmentisai/db";
import { NonRetryableError } from "@qmentisai/infra";
import {
  DEFAULT_BRANCH_TOKEN,
  TRIGGER_DECISION_REASONS,
  computeEffectiveState,
  gateReasonOf,
  nextScheduledFire,
  planScheduledFire,
  resolveScanKind,
  slotKey,
  validateSchedule,
} from "@qmentisai/shared";
import {
  CONFIG_SCHEMA,
  QuotaBlocked,
  UUID,
  createExecutionRequestWriter,
  storedGroup,
} from "../pipeline/execution-request.js";
import { createRouterRepository } from "../pipeline/repository.js";
import { createScheduleRepository } from "./schedule-repository.js";

/** Defaults of the platform limits of the schedule handler (SPEC §6.4, §5.6); the worker configuration overrides them. */
export const SCHEDULE_DEFAULTS = Object.freeze({
  batch: 100,
  maxPerTenantPerTick: 10,
  maxLatenessSeconds: 21600,
  onTimeGraceSeconds: 120,
  jitterSeconds: 300,
});

/** The ref a decision row shows: the trigger's branch, or the repository's default branch (the literal token when it has none). */
const scheduleRefName = (ref, defaultBranch) =>
  (ref === DEFAULT_BRANCH_TOKEN ? (defaultBranch ?? ref) : ref).slice(0, 255);

/**
 * The schedule handler (docs/modules/pipelines-triggers/SPEC.md §6.4), hosted in the scheduler worker: the consumer of the
 * platform job `pipeline.schedules.due_requested`. The job carries no tenant and is naturally idempotent: a repeat finds the
 * triggers already advanced.
 *
 * One run: while the batch is not used up, peek the next due trigger (platform scan on the partial due-schedule index, not
 * tried in this run, tenants that used their share excluded) and handle it in ITS OWN transaction:
 *   advisory lock on the pipeline (the lock of the pipelines API, the router and the manual run; always taken BEFORE the row
 *   lock, the order the API uses) -> claim the trigger row `FOR UPDATE SKIP LOCKED` (a trigger another handler holds or has
 *   already advanced is skipped) -> re-validate everything from the database, scoped by the row's tenant, workspace,
 *   repository and pipeline -> plan (latest pending slot, missed-run policy) -> create the request through the SAME writer as
 *   the SCM router (`../pipeline/execution-request.js`) or record why nothing is created -> advance `next_fire_at`.
 * The request and the advance commit together, so a crash between slots leaves either both or neither; the unique
 * `(tenant, pipeline, schedule_slot)` and the idempotency key are the backstop.
 *
 * Fire-time gates (SPEC §5.2, §6.4): tenant usable, workspace active, repository present in the tenant and workspace, `active`
 * and enabled, pipeline live and enabled, trigger present, enabled and unchanged in the CURRENT configuration version. A
 * pipeline that cannot fire creates nothing; its schedule is advanced to the next slot (no back-fill) and an outcome counter
 * is logged. Schedule syntax or time-zone errors found at fire time deactivate the trigger and are logged as errors; they
 * never stop the batch. A policy/blocking state (repository not active or disabled, workspace archived, pipeline disabled)
 * writes ONE trigger decision row of source type `schedule_slot` per (trigger, slot) in addition to the counter (SPEC §5.9b,
 * §7.8; owner decision 2026-11-13); a repeated run adds nothing (unique key). The fire time of a slot is the slot plus
 * `hash(triggerId + slot) mod window` (`@qmentisai/shared` `nextScheduledFire`, the function the API uses).
 * @param {{
 *   db: any,
 *   config?: { pipelines?: { schedule?: Partial<typeof SCHEDULE_DEFAULTS> } },
 *   logger?: any,
 *   clock?: () => Date,
 * }} deps
 */
export function createScheduleHandler({ db, config, logger, clock = () => new Date() }) {
  const repo = createScheduleRepository({ db });
  const routerRepo = createRouterRepository({ db });
  const writer = createExecutionRequestWriter({ db, clock });
  const limits = { ...SCHEDULE_DEFAULTS, ...config?.pipelines?.schedule };

  /** Moves a trigger on: its planned time, the last handled slot, and (for a trigger that cannot work) `enabled`. */
  const advance = (row, data, tx) =>
    repo.updateTrigger(
      { tenantId: row.tenantId, pipelineId: row.pipelineId, id: row.id, data },
      tx,
    );

  /**
   * Next planned time after now for a trigger (the slot after now plus the jitter of that slot, `hash(triggerId + slot) mod
   * window`: the same function as the API's `next_fire_at`), or null.
   */
  const plannedFromNow = (row, cron, timeZone, now) =>
    nextScheduledFire({
      expression: cron,
      timeZone,
      after: now,
      triggerId: row.id,
      jitterWindowSeconds: limits.jitterSeconds,
    })?.fireAt ?? null;

  /** Everything for ONE claimed due trigger, inside the caller's transaction (and under the pipeline lock). */
  async function handleClaimed(tx, row, now, message) {
    const where = {
      tenantId: row.tenantId,
      workspaceId: row.workspaceId,
      repositoryId: row.repositoryId,
      pipelineId: row.pipelineId,
    };
    const park = (reason, data = {}) =>
      advance(row, { nextFireAt: null, ...data }, tx).then(() => ({ outcome: "parked", reason }));

    const pipeline = await repo.findPipelineForFire(where, tx);
    if (!pipeline || pipeline.deletedAt) return park("pipeline_deleted");
    const version = pipeline.currentConfig;
    const parsed =
      version && version.schemaVersion === 1 ? CONFIG_SCHEMA.safeParse(version.config) : null;
    if (!parsed?.success) return park("invalid_config");
    const cfg = parsed.data;
    // the CURRENT configuration version is the authority: a trigger a later version removed or disabled creates nothing
    const trigger = cfg.triggers.find((t) => t.key === row.triggerKey && t.type === "schedule");
    if (!trigger) return park("trigger_removed", { enabled: false });
    if (!trigger.enabled) return park("trigger_disabled", { enabled: false });
    if (trigger.cron !== row.cron || trigger.timezone !== row.timezone) {
      // the projection is behind the configuration (a hand edit): repair it and plan from now, create nothing
      const check = validateSchedule({ expression: trigger.cron, timeZone: trigger.timezone });
      if (!check.ok) return park("schedule_invalid", { enabled: false });
      await advance(
        row,
        {
          cron: trigger.cron,
          timezone: trigger.timezone,
          missedPolicy: trigger.missedPolicy,
          nextFireAt: plannedFromNow(row, trigger.cron, trigger.timezone, now),
        },
        tx,
      );
      return { outcome: "advanced", reason: "projection_repaired" };
    }
    const check = validateSchedule({ expression: row.cron, timeZone: row.timezone });
    if (!check.ok) return park("schedule_invalid", { enabled: false });

    const plan = planScheduledFire({
      expression: row.cron,
      timeZone: row.timezone,
      triggerId: row.id,
      jitterWindowSeconds: limits.jitterSeconds,
      nextFireAt: row.nextFireAt,
      now,
      missedPolicy: trigger.missedPolicy ?? row.missedPolicy,
      maxLatenessSeconds: limits.maxLatenessSeconds,
      onTimeGraceSeconds: limits.onTimeGraceSeconds,
    });
    const done = (outcome, reason, extra = {}) =>
      advance(row, { nextFireAt: plan.nextFireAt, ...extra }, tx).then(() => ({
        outcome,
        reason,
      }));

    const repository = await repo.findRepositoryForFire(
      { tenantId: row.tenantId, workspaceId: row.workspaceId, repositoryId: row.repositoryId },
      tx,
    );
    if (!repository) return done("skipped_ineligible", "repository_missing");
    const state = computeEffectiveState({
      tenantStatus: repository.tenant.status,
      workspaceStatus: repository.workspace.status,
      repositoryStatus: repository.status,
      repositoryEnabled: repository.enabled,
      pipelineEnabled: pipeline.enabled,
    });
    if (state !== "running_normally") {
      // A policy/blocking state after a match (SPEC §5.9b): the counter stays AND one decision row per (trigger, slot) is
      // written when there is a slot and the reason is one of the decision reasons. A tenant that is not usable
      // (`tenant_unavailable`) and "no slot" have no decision reason: counter only. Nothing is created.
      const reason = gateReasonOf(state);
      if (plan.slot && TRIGGER_DECISION_REASONS.includes(reason))
        await repo.createDecision(
          {
            ...where,
            triggerKey: row.triggerKey,
            scheduleSlot: plan.slot,
            reason,
            refName: scheduleRefName(trigger.ref, repository.defaultBranch),
            correlationId: message.correlationId,
          },
          tx,
        );
      return done("skipped_ineligible", reason);
    }
    if (plan.action === "none" || !plan.slot) return done("advanced", "not_a_slot");

    const slot = plan.slot;
    const slotIso = slotKey(slot);
    const already = () =>
      repo.findExecutionBySlot(
        { tenantId: row.tenantId, pipelineId: row.pipelineId, scheduleSlot: slot },
        tx,
      );
    if (await already()) return done("duplicate", "slot_already_handled", { lastSlotAt: slot });

    // the ref a scheduled run scans: the trigger's branch, or the repository's default branch for `$default_branch`
    const refName = trigger.ref === DEFAULT_BRANCH_TOKEN ? repository.defaultBranch : trigger.ref;
    if (!refName) return done("skipped_ineligible", "no_default_branch");

    const ctx = {
      ...where,
      pipeline: { id: row.pipelineId },
      kind: "schedule",
      commitSha: null,
      messageId: message.messageId,
      initiator: { type: "schedule", id: row.id },
      correlationId: message.correlationId,
      auditCorrelationId: UUID.test(message.correlationId ?? "") ? message.correlationId : null,
    };
    const history = await writer.scanHistory(tx, ctx, cfg);
    const kind = resolveScanKind({
      triggerType: "schedule",
      scanMode: cfg.scanMode,
      requestedKind: trigger.scanKind,
      history,
    });
    const base = {
      ...where,
      configVersionId: version.id,
      configVersion: version.version,
      configHash: version.configHash,
      triggerType: "schedule",
      triggerKey: row.triggerKey,
      scheduleSlot: slot,
      refType: "branch",
      refName: refName.slice(0, 255),
      baseRef: null,
      pullRequestNumber: null,
      commitSha: null,
      baseSha: null,
      scanKind: kind.scanKind,
      scanKindReason: kind.scanKindReason,
      trust: "trusted",
      concurrencyGroup: storedGroup(`schedule:${row.triggerKey}`),
      idempotencyKey: `schedule:${row.triggerKey}:${slotIso}`,
      correlationId: message.correlationId,
    };

    if (plan.action === "missed") {
      // too late (or off the on-time window of the `skip` policy): ONE skipped request for the latest missed slot
      const result = await writer.skipped(tx, ctx, base, "missed_run");
      await advance(row, { nextFireAt: plan.nextFireAt, lastSlotAt: slot }, tx);
      return { ...result, outcome: "missed", latenessSeconds: plan.latenessSeconds };
    }

    // Concurrency policy, quota, the `queued` row and the outbox message. A quota refusal rolls back to the savepoint (the
    // policy's cancellations included) and records a `blocked` row and its audit entry instead.
    await tx.$executeRaw`SAVEPOINT schedule_fire`;
    let result;
    try {
      result = await writer.createRequest(tx, ctx, base, cfg, version);
      await tx.$executeRaw`RELEASE SAVEPOINT schedule_fire`;
    } catch (error) {
      if (!(error instanceof QuotaBlocked)) throw error;
      await tx.$executeRaw`ROLLBACK TO SAVEPOINT schedule_fire`;
      result = await writer.recordBlocked(tx, ctx, error, already);
    }
    await advance(row, { nextFireAt: plan.nextFireAt, lastSlotAt: slot }, tx);
    return {
      ...result,
      latenessSeconds: plan.latenessSeconds,
      skippedEarlier: plan.skippedEarlier,
    };
  }

  /** Plans a trigger that has no planned time yet (SPEC §6.5 "enable recomputes from now", for rows created before the scheduler). */
  async function handleUnscheduled(tx, row, now) {
    const where = {
      tenantId: row.tenantId,
      workspaceId: row.workspaceId,
      repositoryId: row.repositoryId,
      pipelineId: row.pipelineId,
    };
    const pipeline = await repo.findPipelineForFire(where, tx);
    if (!pipeline || pipeline.deletedAt || !pipeline.enabled) return { outcome: "not_planned" };
    const check = validateSchedule({ expression: row.cron, timeZone: row.timezone });
    if (!check.ok) {
      await advance(row, { enabled: false }, tx);
      return { outcome: "parked", reason: "schedule_invalid" };
    }
    await advance(row, { nextFireAt: plannedFromNow(row, row.cron, row.timezone, now) }, tx);
    return { outcome: "planned" };
  }

  /**
   * Handles one platform job. Counters (the outcomes) are returned and logged; one trigger's failure is logged and never stops
   * the others (it is retried at the next tick, because its row was not advanced).
   * @param {any} message the validated `pipeline.schedules.due_requested` job
   * @param {{ log?: any }} [context]
   */
  return async function handleDueSchedules(message, { log = logger } = {}) {
    if (message.type !== "pipeline.schedules.due_requested")
      throw new NonRetryableError(`The schedule handler does not handle "${message.type}".`, {
        reason: "unsupported-message-type",
      });
    const counts = {};
    const bump = (key) => {
      counts[key] = (counts[key] ?? 0) + 1;
    };
    const tried = new Set();
    const perTenant = new Map();
    const capped = new Set();
    for (let attempts = 0; attempts < limits.batch; attempts += 1) {
      const candidate = await repo.peekDue({
        now: clock(),
        excludeIds: [...tried],
        excludeTenantIds: [...capped],
      });
      if (!candidate) break;
      tried.add(candidate.id);
      const used = (perTenant.get(candidate.tenantId) ?? 0) + 1;
      perTenant.set(candidate.tenantId, used);
      if (used >= limits.maxPerTenantPerTick) capped.add(candidate.tenantId);
      try {
        const result = await withTransaction(db, async (tx) => {
          await routerRepo.lockPipeline(
            { tenantId: candidate.tenantId, pipelineId: candidate.pipelineId },
            tx,
          );
          const now = clock();
          const row = await repo.claimDue({ ...candidate, now }, tx);
          if (!row) return { outcome: "not_claimed" };
          return handleClaimed(tx, row, now, message);
        });
        bump(result.outcome);
        log?.info?.(
          {
            metric: "pipeline_schedule_outcome_total",
            outcome: result.outcome,
            reason: result.reason,
            triggerId: candidate.id,
            pipelineId: candidate.pipelineId,
            executionId: result.executionId,
            latenessSeconds: result.latenessSeconds,
          },
          "Schedule trigger handled",
        );
        if (result.outcome === "parked" && result.reason === "schedule_invalid")
          log?.error?.(
            { triggerId: candidate.id, pipelineId: candidate.pipelineId },
            "A schedule trigger has an invalid expression or time zone and was deactivated",
          );
      } catch (error) {
        // a unique violation is the backstop of the slot key: the slot exists, so only the advance is missing
        bump(error?.code === "P2002" ? "duplicate_after_conflict" : "failed");
        log?.error?.(
          { err: error, triggerId: candidate.id, pipelineId: candidate.pipelineId },
          "A schedule trigger could not be handled; it is retried at the next tick",
        );
      }
    }
    // Triggers that have no planned time yet (bounded by the same batch).
    const unplanned = new Set();
    for (let attempts = 0; attempts < limits.batch; attempts += 1) {
      const candidate = await repo.peekUnscheduled({ excludeIds: [...unplanned] });
      if (!candidate) break;
      unplanned.add(candidate.id);
      try {
        const result = await withTransaction(db, async (tx) => {
          await routerRepo.lockPipeline(
            { tenantId: candidate.tenantId, pipelineId: candidate.pipelineId },
            tx,
          );
          const row = await repo.claimUnscheduled(candidate, tx);
          if (!row) return { outcome: "not_claimed" };
          return handleUnscheduled(tx, row, clock());
        });
        bump(result.outcome);
      } catch (error) {
        bump("failed");
        log?.error?.({ err: error, triggerId: candidate.id }, "A schedule could not be planned");
      }
    }
    log?.info?.(
      { messageId: message.messageId, bucket: message.payload.bucket, outcomes: counts },
      "Due schedules handled",
    );
    return counts;
  };
}
