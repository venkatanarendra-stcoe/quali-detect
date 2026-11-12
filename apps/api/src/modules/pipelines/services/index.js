import { randomUUID } from "node:crypto";
import { QUEUE_NAMES, createEventEnvelope } from "@qmentisai/contracts";
import { ENTITLEMENT_KEYS, EntitlementError, QUOTA_KEYS } from "@qmentisai/db";
import {
  ENGINE_CATALOG,
  PIPELINE_SCAN_TYPES,
  PIPELINE_SEVERITIES,
  PIPELINE_TRIGGER_TYPES,
  can,
  checkEnableable,
  evaluatePipelineTriggers,
  forkPolicyOf,
  manualRunBlockOf,
  nextScheduledFire,
  summarizeConfigChange,
  toDryRunDecision,
} from "@qmentisai/shared";
import { AUDIT_ACTIONS } from "../../../audit/actions.js";
import {
  ConflictError,
  ForbiddenError,
  NotFoundError,
  ValidationError,
} from "../../../errors/app-error.js";
import { isUniqueViolation, toPage } from "../../../lib/http.js";
import {
  IN_FLIGHT_EXECUTION_STATUSES,
  MANUAL_GATE_REASONS,
  QUOTA_PERIOD,
  REASONS,
} from "../constants/index.js";
import {
  effectiveStateOf,
  toDecisionDto,
  toExecutionDto,
  toPipelineDto,
  toVersionDto,
  toVersionSummaryDto,
} from "../mappers/index.js";
import { hashConfig, jitterFor, normalizeName, scheduleSignature } from "./helpers.js";

const DAY_MS = 86400000;

/**
 * Pipeline use cases (SPEC §5, §6.1, §6.3, §6.5, §8). Permissions are enforced before (authorize middleware with the
 * pipeline or repository scope, in the pipeline's workspace); here live the business rules: effective state, versions with
 * optimistic concurrency, fork-policy permission, limits, concurrency policy and quota for manual runs. Every change is
 * audited in the SAME transaction; a manual run creates the minimal `queued` execution, consumes the quota and enqueues
 * `pipeline.execution.requested` in ONE transaction.
 * @param {{
 *   repository: ReturnType<typeof import("../repositories/index.js").createPipelineRepository>,
 *   audit: any, outbox: any, entitlements: any,
 *   config: { maxPerRepository: number, limits: Record<string, number> },
 * }} deps
 */
export function createPipelineService({
  repository,
  audit,
  outbox,
  entitlements,
  config: settings,
}) {
  const { limits } = settings;
  const entry = (actor, action, pipeline, extra = {}) => ({
    tenantId: actor.tenantId,
    actorUserId: actor.userId,
    action,
    targetType: "pipeline",
    targetId: pipeline.id,
    workspaceId: pipeline.workspaceId,
    correlationId: actor.requestId,
    ipAddress: actor.ip,
    ...extra,
  });
  const canSeeRepository = (actor, workspaceId) =>
    can(actor.permissions, "repository.view", { type: "workspace", workspaceId });
  const mayManageForkPolicy = (actor, workspaceId) =>
    can(actor.permissions, "pipeline.manage_fork_policy", { type: "workspace", workspaceId });
  const forkPolicyDenied = () =>
    new ForbiddenError("Allowing fork pull requests to run needs additional permission.", {
      details: { reason: REASONS.FORK_POLICY },
    });
  const assertLive = (pipeline) => {
    if (!pipeline || pipeline.deletedAt) throw new NotFoundError();
    return pipeline;
  };
  const conflict = (message, reason, extra = {}) =>
    new ConflictError(message, { details: { reason, ...extra } });
  const incomplete = (missing) =>
    conflict("Enable at least one scan type and one trigger first.", REASONS.PIPELINE_INCOMPLETE, {
      missing,
    });
  const release = async (tx, tenantId, rows) => {
    for (const row of rows)
      if (row.quotaConsumed > 0 && row.quotaPeriod)
        await entitlements.releaseQuota(
          {
            tenantId,
            quotaKey: QUOTA_KEYS.SCANS_MONTHLY,
            amount: row.quotaConsumed,
            periodKey: row.quotaPeriod,
          },
          tx,
        );
  };
  const loadLive = async (tenantId, id, workspaceId, tx) =>
    assertLive(await repository.findPipeline({ tenantId, id, workspaceId }, tx));
  const currentConfigOf = async (tenantId, pipeline, tx) => {
    const version = await repository.findVersionById(
      { tenantId, pipelineId: pipeline.id, id: pipeline.currentVersionId },
      tx,
    );
    if (!version) throw new NotFoundError();
    return version;
  };

  /**
   * Planned fire time (UTC: the next slot after now plus the trigger's jitter) of a schedule trigger, or null when it cannot
   * fire: pipeline disabled, trigger disabled, or a schedule that never fires (SPEC §5.6, §7.2). Never back-fills.
   */
  const plannedFire = ({ pipelineEnabled, enabled, cron, timezone, jitterSeconds }) =>
    pipelineEnabled && enabled
      ? (nextScheduledFire({
          expression: cron,
          timeZone: timezone,
          after: new Date(),
          jitterSeconds,
        })?.fireAt ?? null)
      : null;

  /** Keeps the trigger projection in step with a version (SPEC §7.2): update by key, create, delete stale; schedule state survives an unchanged schedule. */
  async function rebuildTriggers(tx, pipeline, version, config, pipelineEnabled) {
    const { tenantId, id: pipelineId, workspaceId, repositoryId } = pipeline;
    const existing = await repository.listTriggers({ tenantId, pipelineId }, tx);
    const wanted = new Map(config.triggers.map((t) => [t.key, t]));
    const stale = existing.filter((t) => wanted.get(t.triggerKey)?.type !== t.type);
    if (stale.length)
      await repository.deleteTriggers({ tenantId, pipelineId, ids: stale.map((t) => t.id) }, tx);
    const kept = new Map(existing.filter((t) => !stale.includes(t)).map((t) => [t.triggerKey, t]));
    for (const t of config.triggers) {
      const schedule =
        t.type === "schedule"
          ? { cron: t.cron, timezone: t.timezone, missedPolicy: t.missedPolicy }
          : {};
      const base = { enabled: t.enabled, versionId: version.id };
      const old = kept.get(t.key);
      if (old) {
        let fire = {};
        if (t.type === "schedule") {
          const moved = old.cron !== t.cron || old.timezone !== t.timezone;
          const active = pipelineEnabled && t.enabled;
          // an unchanged, still active schedule keeps its planned time; anything else is recomputed from now (or cleared)
          fire =
            active && !moved && old.nextFireAt
              ? {}
              : {
                  nextFireAt: plannedFire({
                    pipelineEnabled,
                    enabled: t.enabled,
                    ...schedule,
                    jitterSeconds: old.jitterOffsetSeconds ?? 0,
                  }),
                };
        }
        await repository.updateTrigger(
          { tenantId, pipelineId, id: old.id, data: { ...base, ...schedule, ...fire } },
          tx,
        );
      } else {
        const id = randomUUID();
        const jitterOffsetSeconds =
          t.type === "schedule" ? jitterFor(id, limits.scheduleJitterSeconds) : undefined;
        await repository.createTrigger(
          {
            tenantId,
            workspaceId,
            repositoryId,
            pipelineId,
            id,
            triggerKey: t.key,
            type: t.type,
            ...base,
            ...schedule,
            ...(t.type === "schedule"
              ? {
                  jitterOffsetSeconds,
                  nextFireAt: plannedFire({
                    pipelineEnabled,
                    enabled: t.enabled,
                    ...schedule,
                    jitterSeconds: jitterOffsetSeconds,
                  }),
                }
              : {}),
          },
          tx,
        );
      }
    }
  }

  /** Enable recomputes every schedule's planned time from now, disable clears them (SPEC §6.5): a pipeline that was off accumulates no misses. */
  async function refreshSchedules(tx, pipeline, pipelineEnabled) {
    const { tenantId, id: pipelineId } = pipeline;
    for (const t of await repository.listTriggers({ tenantId, pipelineId }, tx))
      if (t.type === "schedule")
        await repository.updateTrigger(
          {
            tenantId,
            pipelineId,
            id: t.id,
            data: {
              nextFireAt: plannedFire({
                pipelineEnabled,
                enabled: t.enabled,
                cron: t.cron,
                timezone: t.timezone,
                jitterSeconds: t.jitterOffsetSeconds ?? 0,
              }),
            },
          },
          tx,
        );
  }

  /** Writes one version, moves the pointer, rebuilds the projection and audits the fork policy / schedule changes. */
  async function publishVersion(tx, actor, pipeline, { previous, config, changeNote, enabled }) {
    const next = (previous?.version ?? 0) + 1;
    const summary = summarizeConfigChange(previous?.config ?? null, config);
    const version = await repository.createVersion(
      {
        tenantId: actor.tenantId,
        pipelineId: pipeline.id,
        version: next,
        schemaVersion: config.schemaVersion,
        config,
        configHash: hashConfig(config),
        changeSummary: summary,
        changeNote: changeNote ?? null,
        createdByUserId: actor.userId,
      },
      tx,
    );
    await repository.update(
      {
        tenantId: actor.tenantId,
        id: pipeline.id,
        data: {
          currentVersion: version.version,
          currentVersionId: version.id,
          ...(enabled === undefined ? {} : { enabled }),
        },
      },
      tx,
    );
    await rebuildTriggers(tx, pipeline, version, config, enabled ?? pipeline.enabled);
    const before = forkPolicyOf(previous?.config);
    const after = forkPolicyOf(config);
    if (before !== after)
      await audit.tenant.record(
        entry(actor, AUDIT_ACTIONS.PIPELINE_FORK_POLICY_CHANGED, pipeline, {
          changes: { before: { forkPolicy: before }, after: { forkPolicy: after } },
          metadata: {
            fromVersion: previous?.version ?? null,
            toVersion: version.version,
            configHash: version.configHash,
          },
        }),
        { tx },
      );
    if ((previous ? scheduleSignature(previous.config) : "[]") !== scheduleSignature(config))
      await audit.tenant.record(
        entry(actor, AUDIT_ACTIONS.PIPELINE_SCHEDULE_CHANGED, pipeline, {
          metadata: { version: version.version, configHash: version.configHash },
        }),
        { tx },
      );
    return { version, summary };
  }

  async function listPage(actor, query, extra = {}) {
    const workspaceIds = actor.permissions.workspaces
      .map((w) => w.id)
      .filter((workspaceId) =>
        can(actor.permissions, "pipeline.view", { type: "workspace", workspaceId }),
      );
    const page = await repository.list({
      ...query,
      ...extra,
      tenantId: actor.tenantId,
      workspaceIds,
    });
    const last = new Map(
      (
        await repository.lastRequested({
          tenantId: actor.tenantId,
          pipelineIds: page.items.map((p) => p.id),
        })
      ).map((r) => [r.pipelineId, r]),
    );
    return toPage(
      {
        items: page.items.map((p) =>
          toPipelineDto(p, {
            tenantStatus: actor.tenantStatus,
            canSeeRepository: canSeeRepository(actor, p.workspaceId),
            lastRequest: last.get(p.id) ?? null,
          }),
        ),
        totalItems: page.totalItems,
      },
      query,
    );
  }

  const namesOf = (tenantId, rows) =>
    repository.findMemberNames({
      tenantId,
      userIds: [...new Set(rows.map((r) => r.createdByUserId).filter(Boolean))],
    });

  async function get(actor, ref) {
    const pipeline = await repository.findPipeline({
      tenantId: actor.tenantId,
      id: ref.id,
      workspaceId: ref.workspaceId,
    });
    if (!pipeline) throw new NotFoundError();
    const [last] = await repository.lastRequested({
      tenantId: actor.tenantId,
      pipelineIds: [pipeline.id],
    });
    const skipped = await repository.countDecisionsSince({
      tenantId: actor.tenantId,
      pipelineId: pipeline.id,
      since: new Date(Date.now() - DAY_MS),
    });
    return toPipelineDto(pipeline, {
      tenantStatus: actor.tenantStatus,
      canSeeRepository: canSeeRepository(actor, pipeline.workspaceId),
      lastRequest: last ?? null,
      counters: { skippedByPolicyLast24h: skipped },
    });
  }

  return Object.freeze({
    /** Pipelines of the workspaces where the caller holds pipeline.view (never 403: the set is filtered). */
    list: (actor, query) => listPage(actor, query),

    /** Pipelines of one repository (T-24); the route authorized `pipeline.view` through the repository scope. */
    listForRepository: (actor, repo, query) =>
      listPage(actor, { ...query }, { workspaceId: repo.workspaceId, repositoryId: repo.id }),

    get,

    /** Creates the pipeline, version 1 and the trigger projection in one transaction (SPEC §6.1). */
    async create(actor, repo, input) {
      const forkPolicy = forkPolicyOf(input.config);
      if (forkPolicy !== "skip" && !mayManageForkPolicy(actor, repo.workspaceId))
        throw forkPolicyDenied();
      let created;
      try {
        created = await repository.transaction(async (tx) => {
          const workspace = await repository.findWorkspace(
            { tenantId: actor.tenantId, id: repo.workspaceId },
            tx,
          );
          if (!workspace) throw new NotFoundError();
          if (workspace.status !== "active")
            throw conflict("The workspace is archived.", REASONS.WORKSPACE_ARCHIVED);
          const parent = await repository.findRepository(
            { tenantId: actor.tenantId, workspaceId: repo.workspaceId, id: repo.id },
            tx,
          );
          if (!parent) throw new NotFoundError();
          if (parent.status !== "active")
            throw conflict(
              "Pipelines can only be created on an active repository.",
              REASONS.REPOSITORY_NOT_ACTIVE,
            );
          await repository.lockLimit(actor.tenantId, tx);
          const nameNormalized = normalizeName(input.name);
          if (
            await repository.findByNormalizedName(
              { tenantId: actor.tenantId, repositoryId: parent.id, nameNormalized },
              tx,
            )
          )
            throw conflict(
              "A pipeline with this name already exists on the repository.",
              REASONS.NAME_TAKEN,
            );
          if (
            (await repository.countLiveInRepository(
              { tenantId: actor.tenantId, repositoryId: parent.id },
              tx,
            )) >= settings.maxPerRepository
          )
            throw conflict(
              "This repository has reached its pipeline limit.",
              REASONS.REPOSITORY_PIPELINE_LIMIT,
              {
                limit: settings.maxPerRepository,
              },
            );
          await entitlements.assertWithinLimit(
            {
              tenantId: actor.tenantId,
              key: ENTITLEMENT_KEYS.PIPELINES_MAX,
              currentCount: await repository.countLive({ tenantId: actor.tenantId }, tx),
            },
            tx,
          );
          const enabled = input.enabled === true;
          if (enabled) {
            const check = checkEnableable(input.config);
            if (!check.ok) throw incomplete(check.missing);
          }
          const pipeline = await repository.create(
            {
              tenantId: actor.tenantId,
              workspaceId: parent.workspaceId,
              repositoryId: parent.id,
              name: input.name,
              nameNormalized,
              description: input.description ?? null,
              createdByUserId: actor.userId,
            },
            tx,
          );
          const { version } = await publishVersion(tx, actor, pipeline, {
            previous: null,
            config: input.config,
            enabled,
          });
          await audit.tenant.record(
            entry(actor, AUDIT_ACTIONS.PIPELINE_CREATED, pipeline, {
              metadata: {
                name: pipeline.name,
                repositoryId: parent.id,
                version: version.version,
                configHash: version.configHash,
                enabled,
              },
            }),
            { tx },
          );
          return { pipeline, version };
        });
      } catch (error) {
        if (isUniqueViolation(error))
          throw conflict(
            "A pipeline with this name already exists on the repository.",
            REASONS.NAME_TAKEN,
          );
        throw error;
      }
      const row = await repository.findPipeline({
        tenantId: actor.tenantId,
        id: created.pipeline.id,
      });
      return {
        ...toPipelineDto(row, {
          tenantStatus: actor.tenantStatus,
          canSeeRepository: canSeeRepository(actor, row.workspaceId),
        }),
        version: toVersionDto(created.version, await namesOf(actor.tenantId, [created.version])),
      };
    },

    /** Metadata only (name, description): changed in place and audited; not versioned (PIPE-003). */
    async update(actor, ref, patch) {
      try {
        await repository.transaction(async (tx) => {
          await repository.lockPipeline({ tenantId: actor.tenantId, pipelineId: ref.id }, tx);
          const pipeline = await loadLive(actor.tenantId, ref.id, ref.workspaceId, tx);
          const data = {};
          if (patch.name !== undefined && patch.name !== pipeline.name) {
            const nameNormalized = normalizeName(patch.name);
            if (
              await repository.findByNormalizedName(
                {
                  tenantId: actor.tenantId,
                  repositoryId: pipeline.repositoryId,
                  nameNormalized,
                  excludeId: pipeline.id,
                },
                tx,
              )
            )
              throw conflict(
                "A pipeline with this name already exists on the repository.",
                REASONS.NAME_TAKEN,
              );
            data.name = patch.name;
            data.nameNormalized = nameNormalized;
          }
          if (
            patch.description !== undefined &&
            (patch.description ?? null) !== pipeline.description
          )
            data.description = patch.description ?? null;
          if (Object.keys(data).length === 0) return;
          await repository.update({ tenantId: actor.tenantId, id: pipeline.id, data }, tx);
          const fields = Object.keys(data).filter((k) => k !== "nameNormalized");
          await audit.tenant.record(
            entry(actor, AUDIT_ACTIONS.PIPELINE_UPDATED, pipeline, {
              changes: {
                before: Object.fromEntries(fields.map((f) => [f, pipeline[f]])),
                after: Object.fromEntries(fields.map((f) => [f, data[f]])),
              },
            }),
            { tx },
          );
        });
      } catch (error) {
        if (isUniqueViolation(error))
          throw conflict(
            "A pipeline with this name already exists on the repository.",
            REASONS.NAME_TAKEN,
          );
        throw error;
      }
      return get(actor, ref);
    },

    async listVersions(actor, ref, query) {
      const page = await repository.listVersions({
        tenantId: actor.tenantId,
        pipelineId: ref.id,
        ...query,
      });
      const names = await namesOf(actor.tenantId, page.items);
      return toPage(
        {
          items: page.items.map((v) => toVersionSummaryDto(v, names)),
          totalItems: page.totalItems,
        },
        query,
      );
    },

    async getVersion(actor, ref, version) {
      const row = await repository.findVersion({
        tenantId: actor.tenantId,
        pipelineId: ref.id,
        version,
      });
      if (!row) throw new NotFoundError();
      return toVersionDto(row, await namesOf(actor.tenantId, [row]));
    },

    /**
     * Publishes configuration version N+1 (SPEC R-3): optimistic concurrency on `expectedVersion`, fork-policy permission
     * (needs `pipeline.manage_fork_policy` when the new policy is not `skip` and differs from the current one), and the
     * R-4 completeness rule while the pipeline is enabled. Versions are never updated: an edit is a new row.
     */
    async publishConfig(actor, ref, { expectedVersion, config, changeNote }) {
      const version = await repository.transaction(async (tx) => {
        await repository.lockPipeline({ tenantId: actor.tenantId, pipelineId: ref.id }, tx);
        const pipeline = await loadLive(actor.tenantId, ref.id, ref.workspaceId, tx);
        if (pipeline.currentVersion !== expectedVersion)
          throw conflict(
            "The configuration changed since you opened it.",
            REASONS.VERSION_CONFLICT,
            {
              currentVersion: pipeline.currentVersion,
            },
          );
        const previous = await currentConfigOf(actor.tenantId, pipeline, tx);
        const next = forkPolicyOf(config);
        if (
          next !== "skip" &&
          next !== forkPolicyOf(previous.config) &&
          !mayManageForkPolicy(actor, pipeline.workspaceId)
        )
          throw forkPolicyDenied();
        if (pipeline.enabled) {
          const check = checkEnableable(config);
          if (!check.ok) throw incomplete(check.missing);
        }
        const published = await publishVersion(tx, actor, pipeline, {
          previous,
          config,
          changeNote,
        });
        await audit.tenant.record(
          entry(actor, AUDIT_ACTIONS.PIPELINE_CONFIG_PUBLISHED, pipeline, {
            metadata: {
              fromVersion: previous.version,
              toVersion: published.version.version,
              configHash: published.version.configHash,
              diff: published.summary,
              ...(changeNote ? { changeNote } : {}),
            },
          }),
          { tx },
        );
        return published.version;
      });
      return toVersionDto(version, await namesOf(actor.tenantId, [version]));
    },

    async setEnabled(actor, ref, enabled) {
      await repository.transaction(async (tx) => {
        await repository.lockPipeline({ tenantId: actor.tenantId, pipelineId: ref.id }, tx);
        const pipeline = await loadLive(actor.tenantId, ref.id, ref.workspaceId, tx);
        if (pipeline.enabled === enabled) return;
        const version = await currentConfigOf(actor.tenantId, pipeline, tx);
        if (enabled) {
          const check = checkEnableable(version.config);
          if (!check.ok) throw incomplete(check.missing);
        }
        await repository.update(
          { tenantId: actor.tenantId, id: pipeline.id, data: { enabled } },
          tx,
        );
        await refreshSchedules(tx, pipeline, enabled);
        await audit.tenant.record(
          entry(
            actor,
            enabled ? AUDIT_ACTIONS.PIPELINE_ENABLED : AUDIT_ACTIONS.PIPELINE_DISABLED,
            pipeline,
            {
              metadata: { version: version.version },
            },
          ),
          { tx },
        );
      });
      return get(actor, ref);
    },

    /** Soft delete (R-5): refused while a non-queued execution is active; queued requests are cancelled and their quota released. */
    async remove(actor, ref, { confirm }) {
      const pipeline = assertLive(
        await repository.findPipeline({
          tenantId: actor.tenantId,
          id: ref.id,
          workspaceId: ref.workspaceId,
        }),
      );
      if (confirm !== pipeline.name)
        throw new ValidationError(
          [
            {
              path: "confirm",
              code: "confirmation_mismatch",
              message: "Type the pipeline name exactly to confirm.",
            },
          ],
          { source: "body" },
        );
      await repository.transaction(async (tx) => {
        await repository.lockPipeline({ tenantId: actor.tenantId, pipelineId: pipeline.id }, tx);
        const live = await loadLive(actor.tenantId, pipeline.id, pipeline.workspaceId, tx);
        if (
          await repository.hasActiveExecutions(
            { tenantId: actor.tenantId, pipelineId: live.id },
            tx,
          )
        )
          throw conflict("Cancel the running executions first.", REASONS.HAS_ACTIVE_EXECUTIONS);
        const cancelled = await repository.cancelQueued(
          { tenantId: actor.tenantId, pipelineId: live.id, reason: "pipeline_deleted" },
          tx,
        );
        await release(tx, actor.tenantId, cancelled);
        await repository.deleteTriggers({ tenantId: actor.tenantId, pipelineId: live.id }, tx);
        await repository.update(
          {
            tenantId: actor.tenantId,
            id: live.id,
            data: { deletedAt: new Date(), deletedByUserId: actor.userId },
          },
          tx,
        );
        await audit.tenant.record(
          entry(actor, AUDIT_ACTIONS.PIPELINE_DELETED, live, {
            metadata: { name: live.name, cancelledQueued: cancelled.length },
          }),
          { tx },
        );
      });
      return { deleted: true };
    },

    async listExecutions(actor, ref, query) {
      const page = await repository.listExecutions({
        tenantId: actor.tenantId,
        pipelineId: ref.id,
        ...query,
      });
      return toPage({ items: page.items.map(toExecutionDto), totalItems: page.totalItems }, query);
    },

    async listDecisions(actor, ref, query) {
      const page = await repository.listDecisions({
        tenantId: actor.tenantId,
        pipelineId: ref.id,
        ...query,
      });
      return toPage({ items: page.items.map(toDecisionDto), totalItems: page.totalItems }, query);
    },

    /**
     * Manual run (SPEC §5.6, §6.3). One transaction: gates, idempotency, concurrency policy, quota, the `queued` row and the
     * outbox message. A denial rolls everything back and is audited as `execution.manual_denied` OUTSIDE that transaction.
     * `idempotencyKey` is the validated `Idempotency-Key` header; the stored key is `manual:<userId>:<header>`.
     */
    async run(actor, ref, input, idempotencyKey) {
      const key = `manual:${actor.userId}:${idempotencyKey}`;
      let outcome;
      try {
        outcome = await repository.transaction(async (tx) => {
          await repository.lockPipeline({ tenantId: actor.tenantId, pipelineId: ref.id }, tx);
          const pipeline = await loadLive(actor.tenantId, ref.id, ref.workspaceId, tx);
          const replay = await repository.findExecutionByKey(
            { tenantId: actor.tenantId, pipelineId: pipeline.id, idempotencyKey: key },
            tx,
          );
          if (replay) return replay;
          const blocked = manualRunBlockOf(effectiveStateOf(pipeline, actor.tenantStatus));
          if (blocked) throw conflict(MANUAL_BLOCK_MESSAGES[blocked], blocked);
          const version = await currentConfigOf(actor.tenantId, pipeline, tx);
          const manual = version.config.triggers?.find((t) => t.type === "manual");
          if (!manual?.enabled)
            throw conflict(
              "Manual runs are switched off for this pipeline.",
              REASONS.MANUAL_DISABLED,
            );
          const refType = input.ref?.type ?? "branch";
          const refName = input.ref?.name ?? pipeline.repository.defaultBranch;
          if (!refName)
            throw new ValidationError(
              [
                {
                  path: "ref",
                  code: "required",
                  message: "Choose a branch or tag: the repository has no default branch.",
                },
              ],
              { source: "body" },
            );
          const group = `manual:${refName}`;
          const policy = version.config.execution?.concurrency ?? {};
          const base = {
            tenantId: actor.tenantId,
            workspaceId: pipeline.workspaceId,
            repositoryId: pipeline.repositoryId,
            pipelineId: pipeline.id,
            configVersionId: version.id,
            configVersion: version.version,
            configHash: version.configHash,
            triggerType: "manual",
            triggerKey: manual.key,
            requestedByUserId: actor.userId,
            refType,
            refName,
            scanKind: input.scanKind ?? "full",
            scanKindReason: "manual",
            trust: "trusted",
            concurrencyGroup: group,
            idempotencyKey: key,
            correlationId: actor.requestId,
          };
          const skip = async (reason) => {
            const row = await repository.createExecution(
              { ...base, status: "skipped", statusReason: reason },
              tx,
            );
            await audit.tenant.record(
              entry(actor, AUDIT_ACTIONS.EXECUTION_SKIPPED, pipeline, {
                metadata: { executionId: row.id, reason, triggerType: "manual", refName },
              }),
              { tx },
            );
            return row;
          };
          if (policy.policy === "skip") {
            const busy = await repository.countExecutions(
              {
                tenantId: actor.tenantId,
                pipelineId: pipeline.id,
                statuses: [...IN_FLIGHT_EXECUTION_STATUSES],
                concurrencyGroup: group,
              },
              tx,
            );
            if (busy > 0) return skip("concurrency_skip");
          } else if (policy.policy === "queue") {
            const queued = await repository.countExecutions(
              { tenantId: actor.tenantId, pipelineId: pipeline.id, statuses: ["queued"] },
              tx,
            );
            if (queued >= (policy.maxQueued ?? 0)) return skip("queue_full");
          } else {
            const superseded = await repository.cancelQueued(
              {
                tenantId: actor.tenantId,
                pipelineId: pipeline.id,
                concurrencyGroup: group,
                reason: "superseded",
              },
              tx,
            );
            await release(tx, actor.tenantId, superseded);
            for (const row of superseded)
              await audit.tenant.record(
                entry(actor, AUDIT_ACTIONS.EXECUTION_CANCELLED_SUPERSEDED, pipeline, {
                  metadata: { executionId: row.id, triggerType: "manual", refName },
                }),
                { tx },
              );
          }
          const period = QUOTA_PERIOD();
          await entitlements.consumeQuota(
            {
              tenantId: actor.tenantId,
              quotaKey: QUOTA_KEYS.SCANS_MONTHLY,
              amount: 1,
              periodKey: period,
            },
            tx,
          );
          const row = await repository.createExecution(
            { ...base, status: "queued", quotaPeriod: period, quotaConsumed: 1 },
            tx,
          );
          await outbox.enqueue(tx, {
            queue: QUEUE_NAMES.PIPELINE,
            message: createEventEnvelope({
              messageId: `execution-requested-${row.id}`,
              type: "pipeline.execution.requested",
              schemaVersion: 1,
              tenantId: actor.tenantId,
              workspaceId: pipeline.workspaceId,
              repositoryId: pipeline.repositoryId,
              pipelineId: pipeline.id,
              executionId: row.id,
              correlationId: actor.requestId,
              initiator: { type: "user", id: actor.userId },
              subject: { type: "execution", id: row.id },
              payload: {
                executionId: row.id,
                pipelineId: pipeline.id,
                repositoryId: pipeline.repositoryId,
                workspaceId: pipeline.workspaceId,
                configVersion: version.version,
                configHash: version.configHash,
                triggerType: "manual",
                triggerKey: manual.key,
                refType,
                refName,
                commitSha: null,
                pullRequestNumber: null,
                scanKind: row.scanKind,
                scanKindReason: "manual",
                trust: "trusted",
              },
            }),
          });
          await audit.tenant.record(
            entry(actor, AUDIT_ACTIONS.EXECUTION_MANUAL_REQUESTED, pipeline, {
              metadata: {
                executionId: row.id,
                version: version.version,
                configHash: version.configHash,
                refType,
                refName,
                scanKind: row.scanKind,
              },
            }),
            { tx },
          );
          return row;
        });
      } catch (error) {
        const reason = denialReason(error);
        if (reason)
          await audit.tenant.record(
            entry(actor, AUDIT_ACTIONS.EXECUTION_MANUAL_DENIED, ref, {
              metadata: {
                reason,
                ...(input.ref ? { refType: input.ref.type, refName: input.ref.name } : {}),
              },
            }),
          );
        else if (isUniqueViolation(error)) {
          // the same Idempotency-Key raced past the replay lookup: the winner's row is the answer
          const winner = await repository.findExecutionByKey({
            tenantId: actor.tenantId,
            pipelineId: ref.id,
            idempotencyKey: key,
          });
          if (winner) return { execution: toExecutionDto(winner) };
        }
        throw error;
      }
      return { execution: toExecutionDto(outcome) };
    },

    /** Records the denial of a manual run on a pipeline the caller can see but may not run (route policy). */
    async recordRunPermissionDenied(actor, ref) {
      await audit.tenant.record(
        entry(actor, AUDIT_ACTIONS.EXECUTION_MANUAL_DENIED, ref, {
          metadata: { reason: REASONS.PERMISSION_DENIED },
        }),
      );
    },

    /** Dry-run (SPEC §8): the same matcher and effective-state function as the worker; no row, no quota, no audit. */
    async dryRun(actor, repo, body) {
      const pipelines = await repository.listForRepository({
        tenantId: actor.tenantId,
        workspaceId: repo.workspaceId,
        repositoryId: repo.id,
        id: body.pipelineId,
      });
      if (body.pipelineId && pipelines.length === 0) throw new NotFoundError();
      const event =
        body.event === "push"
          ? {
              kind: "push",
              ref: body.tag !== undefined ? `refs/tags/${body.tag}` : `refs/heads/${body.branch}`,
              branch: body.tag !== undefined ? null : body.branch,
              created: body.created,
              deleted: body.deleted,
              forced: body.forced,
            }
          : {
              kind: "pull_request",
              action: body.action,
              number: body.number,
              baseRef: body.baseRef,
              headRef: body.headRef ?? null,
              isFork: body.isFork,
              draft: body.draft,
              merged: body.merged,
            };
      const items = pipelines.map((p) => {
        const effectiveState = effectiveStateOf(p, actor.tenantStatus);
        const evaluations = evaluatePipelineTriggers({
          config: p.currentConfig?.config,
          event,
          repository: { defaultBranch: p.repository.defaultBranch },
          effectiveState,
        });
        return {
          pipelineId: p.id,
          pipelineName: p.name,
          effectiveState,
          triggers: evaluations.map((e) => ({
            triggerKey: e.triggerKey,
            triggerType: e.triggerType,
            decision: toDryRunDecision(e),
            reasons: e.reasons,
            scanKind: e.scanKind,
            trust: e.trust,
          })),
        };
      });
      return { items, quota: "unknown" };
    },

    /** One source for the wizard's validation hints (SPEC §8 `options`). */
    async options(actor) {
      const entitlement = await entitlements.checkEntitlement({
        tenantId: actor.tenantId,
        key: ENTITLEMENT_KEYS.PIPELINES_MAX,
      });
      return {
        limits: { ...limits },
        triggerTypes: [...PIPELINE_TRIGGER_TYPES],
        scanTypes: [...PIPELINE_SCAN_TYPES],
        severities: [...PIPELINE_SEVERITIES],
        engines: Object.fromEntries(
          PIPELINE_SCAN_TYPES.map((type) => [
            type,
            Object.entries(ENGINE_CATALOG[type]).map(([id, e]) => ({
              id,
              name: e.name,
              profiles: [...e.profiles],
            })),
          ]),
        ),
        pipelines: {
          used: await repository.countLive({ tenantId: actor.tenantId }),
          limit: entitlement.enabled ? entitlement.limit : 0,
        },
      };
    },
  });
}

const MANUAL_BLOCK_MESSAGES = Object.freeze({
  [REASONS.PIPELINE_DISABLED]: "The pipeline is disabled.",
  [REASONS.REPOSITORY_NOT_ACTIVE]: "The repository is not active.",
  [REASONS.WORKSPACE_ARCHIVED]: "The workspace is archived.",
});

/** The audited reason of a refused manual run, or null when the error is not a denial. @param {unknown} error */
function denialReason(error) {
  if (error instanceof ConflictError && MANUAL_GATE_REASONS.includes(error.details?.reason))
    return error.details.reason;
  if (error instanceof EntitlementError)
    return error.code === "QUOTA_EXCEEDED" ? REASONS.QUOTA_EXCEEDED : REASONS.ENTITLEMENT_REQUIRED;
  return null;
}
