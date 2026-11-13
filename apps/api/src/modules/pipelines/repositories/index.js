import { toPrismaOrderBy, toPrismaPaging } from "../../../lib/query.js";
import { ACTIVE_EXECUTION_STATUSES } from "../constants/index.js";

/** Rows of one effective state, mirroring `computeEffectiveState` in @qmentisai/shared (same precedence). */
const EFFECTIVE_STATE_WHERE = Object.freeze({
  disabled: { enabled: false },
  workspace_archived: { enabled: true, workspace: { status: "archived" } },
  repository_disconnected: {
    enabled: true,
    workspace: { status: "active" },
    repository: { status: "disconnected" },
  },
  repository_unavailable: {
    enabled: true,
    workspace: { status: "active" },
    repository: { status: "unavailable" },
  },
  repository_disabled: {
    enabled: true,
    workspace: { status: "active" },
    repository: { status: "active", enabled: false },
  },
  running_normally: {
    enabled: true,
    workspace: { status: "active" },
    repository: { status: "active", enabled: true },
  },
});

const PIPELINE_INCLUDE = Object.freeze({
  repository: {
    select: {
      id: true,
      name: true,
      fullName: true,
      displayName: true,
      status: true,
      enabled: true,
      archived: true,
      defaultBranch: true,
    },
  },
  workspace: { select: { id: true, status: true } },
  currentConfig: {
    select: {
      id: true,
      version: true,
      schemaVersion: true,
      configHash: true,
      changeNote: true,
      createdByUserId: true,
      createdAt: true,
    },
  },
  triggers: {
    select: { triggerKey: true, type: true, enabled: true, nextFireAt: true },
    orderBy: { triggerKey: "asc" },
  },
});

/**
 * Data access of the pipelines module (SPEC §7). EVERY function carries the trusted `tenantId` in its `where`; workspace and
 * repository ids are added wherever the caller knows them, so a pipeline is never read or changed by id alone and the
 * parent chain (tenant, workspace, repository, pipeline) is always checked. `client` is the Prisma client or a transaction.
 * Prisma stays inside this file.
 * @param {{ db: any }} deps
 */
export function createPipelineRepository({ db }) {
  /** The latest execution request of each pipeline (one per pipeline). */
  const lastRequested = ({ tenantId, pipelineIds }, client = db) =>
    pipelineIds.length === 0
      ? []
      : client.$queryRaw`
          SELECT DISTINCT ON (pipeline_id) pipeline_id AS "pipelineId", id, status, status_reason AS "statusReason",
                 requested_at AS "requestedAt"
          FROM executions
          WHERE tenant_id = ${tenantId}::uuid AND pipeline_id = ANY(${pipelineIds}::uuid[])
          ORDER BY pipeline_id, requested_at DESC`;
  return Object.freeze({
    transaction: (fn) => db.$transaction(fn),

    // ---- locks (transaction scoped; per tenant for limits, per pipeline for every mutation and run)
    lockLimit: (tenantId, client) =>
      client.$executeRaw`SELECT pg_advisory_xact_lock(hashtext(${`limit:pipelines:${tenantId}`}))`,
    lockPipeline: ({ tenantId, pipelineId }, client) =>
      client.$executeRaw`SELECT pg_advisory_xact_lock(hashtext(${`pipeline:${tenantId}:${pipelineId}`}))`,

    // ---- parents
    findRepository: ({ tenantId, workspaceId, id }, client = db) =>
      client.repository.findFirst({
        where: { tenantId, ...(workspaceId ? { workspaceId } : {}), id },
      }),
    findWorkspace: ({ tenantId, id }, client = db) =>
      client.workspace.findFirst({ where: { tenantId, id }, select: { id: true, status: true } }),

    // ---- pipelines
    /** Id and workspace of a pipeline of this tenant (to audit a permission denial). */
    findRef: ({ tenantId, id }, client = db) =>
      client.pipeline.findFirst({
        where: { tenantId, id },
        select: { id: true, workspaceId: true },
      }),
    findPipeline: ({ tenantId, id, workspaceId }, client = db) =>
      client.pipeline.findFirst({
        where: { tenantId, id, ...(workspaceId ? { workspaceId } : {}) },
        include: PIPELINE_INCLUDE,
      }),
    /** Non-deleted pipelines of ONE repository (workspace and repository checked), optionally one of them. */
    listForRepository: ({ tenantId, workspaceId, repositoryId, id }, client = db) =>
      client.pipeline.findMany({
        where: { tenantId, workspaceId, repositoryId, deletedAt: null, ...(id ? { id } : {}) },
        include: {
          ...PIPELINE_INCLUDE,
          currentConfig: { select: { ...PIPELINE_INCLUDE.currentConfig.select, config: true } },
        },
        orderBy: { name: "asc" },
        take: 200,
      }),
    async list({
      tenantId,
      workspaceIds,
      workspaceId,
      repositoryId,
      enabled,
      effectiveState,
      triggerType,
      q,
      includeDeleted,
      sort,
      page,
      pageSize,
    }) {
      const stateWhere =
        effectiveState && effectiveState !== "deleted"
          ? EFFECTIVE_STATE_WHERE[effectiveState]
          : null;
      const where = {
        tenantId,
        workspaceId: workspaceId
          ? { in: workspaceIds.filter((id) => id === workspaceId) }
          : { in: workspaceIds },
        ...(repositoryId ? { repositoryId } : {}),
        ...(effectiveState === "deleted"
          ? { deletedAt: { not: null } }
          : includeDeleted
            ? {}
            : { deletedAt: null }),
        ...(enabled === undefined ? {} : { enabled }),
        ...(stateWhere ?? {}),
        ...(triggerType ? { triggers: { some: { type: triggerType } } } : {}),
        ...(q ? { name: { contains: q, mode: "insensitive" } } : {}),
      };
      const sortsByLastRequest = sort.some((s) => s.field === "lastRequestedAt");
      if (!sortsByLastRequest) {
        const [items, totalItems] = await Promise.all([
          db.pipeline.findMany({
            where,
            include: PIPELINE_INCLUDE,
            orderBy: toPrismaOrderBy(sort),
            ...toPrismaPaging({ page, pageSize }),
          }),
          db.pipeline.count({ where }),
        ]);
        return { items, totalItems };
      }
      // `lastRequestedAt` is an aggregate over executions: order the (bounded) id set in memory, then load one page.
      const all = await db.pipeline.findMany({
        where,
        select: { id: true, name: true },
        orderBy: { name: "asc" },
        take: 5000,
      });
      const latest = new Map(
        (await lastRequested({ tenantId, pipelineIds: all.map((p) => p.id) })).map((r) => [
          r.pipelineId,
          r.requestedAt.getTime(),
        ]),
      );
      const direction =
        sort.find((s) => s.field === "lastRequestedAt").direction === "desc" ? -1 : 1;
      const ordered = [...all].sort((a, b) => {
        const x = latest.get(a.id) ?? -1;
        const y = latest.get(b.id) ?? -1;
        return x === y ? a.name.localeCompare(b.name) : direction * (x - y);
      });
      const ids = ordered.slice((page - 1) * pageSize, page * pageSize).map((p) => p.id);
      const rows = ids.length
        ? await db.pipeline.findMany({
            where: { tenantId, id: { in: ids } },
            include: PIPELINE_INCLUDE,
          })
        : [];
      const byId = new Map(rows.map((r) => [r.id, r]));
      return { items: ids.map((id) => byId.get(id)).filter(Boolean), totalItems: all.length };
    },
    lastRequested,
    countLive: ({ tenantId }, client = db) =>
      client.pipeline.count({ where: { tenantId, deletedAt: null } }),
    countLiveInRepository: ({ tenantId, repositoryId }, client = db) =>
      client.pipeline.count({ where: { tenantId, repositoryId, deletedAt: null } }),
    /** Non-deleted pipelines per repository, for the repository DTO's `pipelineCount`. @returns {Promise<Map<string, number>>} */
    async countByRepository({ tenantId, repositoryIds }, client = db) {
      if (repositoryIds.length === 0) return new Map();
      const rows = await client.pipeline.groupBy({
        by: ["repositoryId"],
        where: { tenantId, repositoryId: { in: repositoryIds }, deletedAt: null },
        _count: { _all: true },
      });
      return new Map(rows.map((r) => [r.repositoryId, r._count._all]));
    },
    findByNormalizedName: ({ tenantId, repositoryId, nameNormalized, excludeId }, client = db) =>
      client.pipeline.findFirst({
        where: {
          tenantId,
          repositoryId,
          nameNormalized,
          deletedAt: null,
          ...(excludeId ? { id: { not: excludeId } } : {}),
        },
        select: { id: true },
      }),
    create: ({ tenantId, workspaceId, repositoryId, ...data }, client = db) =>
      client.pipeline.create({ data: { tenantId, workspaceId, repositoryId, ...data } }),
    update: ({ tenantId, id, data }, client = db) =>
      client.pipeline.updateMany({ where: { id, tenantId, deletedAt: null }, data }),

    // ---- versions
    createVersion: ({ tenantId, pipelineId, ...data }, client = db) =>
      client.pipelineConfigVersion.create({ data: { tenantId, pipelineId, ...data } }),
    findVersion: ({ tenantId, pipelineId, version }, client = db) =>
      client.pipelineConfigVersion.findFirst({ where: { tenantId, pipelineId, version } }),
    findVersionById: ({ tenantId, pipelineId, id }, client = db) =>
      client.pipelineConfigVersion.findFirst({ where: { tenantId, pipelineId, id } }),
    async listVersions({ tenantId, pipelineId, page, pageSize }) {
      const where = { tenantId, pipelineId };
      const [items, totalItems] = await Promise.all([
        db.pipelineConfigVersion.findMany({
          where,
          orderBy: { version: "desc" },
          select: {
            id: true,
            version: true,
            schemaVersion: true,
            configHash: true,
            changeSummary: true,
            changeNote: true,
            createdByUserId: true,
            createdAt: true,
          },
          ...toPrismaPaging({ page, pageSize }),
        }),
        db.pipelineConfigVersion.count({ where }),
      ]);
      return { items, totalItems };
    },
    /** Display names of users who are MEMBERS of this tenant (users are global rows; membership scopes the lookup). */
    async findMemberNames({ tenantId, userIds }, client = db) {
      if (userIds.length === 0) return new Map();
      const rows = await client.tenantMembership.findMany({
        where: { tenantId, userId: { in: userIds } },
        select: { user: { select: { id: true, name: true } } },
      });
      return new Map(rows.map((r) => [r.user.id, r.user.name]));
    },

    // ---- trigger projection (rebuildable from the current version)
    listTriggers: ({ tenantId, pipelineId }, client = db) =>
      client.pipelineTrigger.findMany({ where: { tenantId, pipelineId } }),
    createTrigger: ({ tenantId, workspaceId, repositoryId, pipelineId, ...data }, client = db) =>
      client.pipelineTrigger.create({
        data: { tenantId, workspaceId, repositoryId, pipelineId, ...data },
      }),
    updateTrigger: ({ tenantId, pipelineId, id, data }, client = db) =>
      client.pipelineTrigger.updateMany({ where: { id, tenantId, pipelineId }, data }),
    deleteTriggers: ({ tenantId, pipelineId, ids }, client = db) =>
      client.pipelineTrigger.deleteMany({
        where: { tenantId, pipelineId, ...(ids ? { id: { in: ids } } : {}) },
      }),

    // ---- executions (minimal rows written by this module)
    async listExecutions({ tenantId, pipelineId, status, triggerType, page, pageSize }) {
      const where = {
        tenantId,
        pipelineId,
        ...(status ? { status } : {}),
        ...(triggerType ? { triggerType } : {}),
      };
      const [items, totalItems] = await Promise.all([
        db.execution.findMany({
          where,
          orderBy: { requestedAt: "desc" },
          select: {
            id: true,
            status: true,
            statusReason: true,
            triggerType: true,
            refName: true,
            refType: true,
            pullRequestNumber: true,
            commitSha: true,
            scanKind: true,
            trust: true,
            requestedAt: true,
          },
          ...toPrismaPaging({ page, pageSize }),
        }),
        db.execution.count({ where }),
      ]);
      return { items, totalItems };
    },
    findExecution: ({ tenantId, pipelineId, id }, client = db) =>
      client.execution.findFirst({ where: { tenantId, pipelineId, id } }),
    findExecutionByKey: ({ tenantId, pipelineId, idempotencyKey }, client = db) =>
      client.execution.findFirst({ where: { tenantId, pipelineId, idempotencyKey } }),
    createExecution: ({ tenantId, workspaceId, repositoryId, pipelineId, ...data }, client = db) =>
      client.execution.create({
        data: { tenantId, workspaceId, repositoryId, pipelineId, ...data },
      }),
    hasActiveExecutions: async ({ tenantId, pipelineId }, client = db) =>
      (await client.execution.count({
        where: { tenantId, pipelineId, status: { in: [...ACTIVE_EXECUTION_STATUSES] } },
      })) > 0,
    countExecutions: ({ tenantId, pipelineId, statuses, concurrencyGroup }, client = db) =>
      client.execution.count({
        where: {
          tenantId,
          pipelineId,
          status: { in: statuses },
          ...(concurrencyGroup ? { concurrencyGroup } : {}),
        },
      }),
    /**
     * Cancels the queued requests of a pipeline (optionally of one concurrency group) with a conditional update per row and
     * returns exactly what was cancelled, with the quota to give back.
     * @returns {Promise<Array<{ id: string, quotaPeriod: string | null, quotaConsumed: number }>>}
     */
    async cancelQueued({ tenantId, pipelineId, concurrencyGroup, reason }, client = db) {
      const rows = await client.execution.findMany({
        where: {
          tenantId,
          pipelineId,
          status: "queued",
          ...(concurrencyGroup ? { concurrencyGroup } : {}),
        },
        select: { id: true, quotaPeriod: true, quotaConsumed: true },
      });
      const cancelled = [];
      for (const row of rows) {
        const done = await client.execution.updateMany({
          where: { id: row.id, tenantId, pipelineId, status: "queued" },
          data: { status: "cancelled", statusReason: reason },
        });
        if (done.count === 1) cancelled.push(row);
      }
      return cancelled;
    },

    // ---- trigger decisions (insert-only, written by the router and the schedule handler; read here)
    async listDecisions({ tenantId, pipelineId, reason, triggerType, sourceType, page, pageSize }) {
      const where = {
        tenantId,
        pipelineId,
        ...(reason ? { reason } : {}),
        ...(triggerType ? { triggerType } : {}),
        ...(sourceType ? { sourceType } : {}),
      };
      const [items, totalItems] = await Promise.all([
        db.pipelineTriggerDecision.findMany({
          where,
          orderBy: { decidedAt: "desc" },
          select: {
            id: true,
            decidedAt: true,
            decision: true,
            reason: true,
            sourceType: true,
            scmDeliveryId: true,
            scheduleSlot: true,
            manualKey: true,
            triggerType: true,
            triggerKey: true,
            refType: true,
            refName: true,
            pullRequestNumber: true,
          },
          ...toPrismaPaging({ page, pageSize }),
        }),
        db.pipelineTriggerDecision.count({ where }),
      ]);
      return { items, totalItems };
    },
    countDecisionsSince: ({ tenantId, pipelineId, since }, client = db) =>
      client.pipelineTriggerDecision.count({
        // a `cancelled_pr_closed` row is housekeeping, not a skipped event: it does not count as "skipped by policy"
        where: {
          tenantId,
          pipelineId,
          decidedAt: { gte: since },
          reason: { not: "cancelled_pr_closed" },
        },
      }),
  });
}
