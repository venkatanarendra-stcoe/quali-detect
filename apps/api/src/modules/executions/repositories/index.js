import {
  createExecutionCancellation,
  createExecutionReadRepository,
  createExecutionRepository,
} from "@qmentisai/db";

/** Columns of an execution the DTOs read. NEVER the lease, the archive, the idempotency key or the correlation id. */
const EXECUTION_COLUMNS = {
  id: true,
  workspaceId: true,
  repositoryId: true,
  pipelineId: true,
  status: true,
  statusReason: true,
  triggerType: true,
  triggerKey: true,
  refType: true,
  refName: true,
  pullRequestNumber: true,
  commitSha: true,
  scanKind: true,
  scanKindReason: true,
  trust: true,
  requestedAt: true,
  startedAt: true,
  finishedAt: true,
  cancelRequestedAt: true,
  retryOfExecutionId: true,
};
const DETAIL_COLUMNS = {
  configVersionId: true,
  configVersion: true,
  configHash: true,
  requestedByUserId: true,
  baseRef: true,
  deadlineAt: true,
  cancelMode: true,
  statusRev: true,
};

/**
 * Data access of the executions module's write side (SPEC executions part D). EVERY function carries the trusted `tenantId`
 * in its `where`; an execution is never read or changed by id alone, and the parent chain (tenant, workspace, repository,
 * pipeline) is checked wherever the caller knows it. `client` is the Prisma client or a transaction. Prisma stays inside the
 * repository layer (this file and `@qmentisai/db`).
 * @param {{ db: any }} deps
 */
export function createExecutionsRepository({ db }) {
  const cancellation = createExecutionCancellation({ db });
  const executions = createExecutionRepository({ db });
  const reads = createExecutionReadRepository({ db });
  return Object.freeze({
    transaction: (fn) => db.$transaction(fn),

    /** Same advisory lock every pipeline writer takes (`pipeline:<tenant>:<id>`): retries serialize with runs and claims. */
    lockPipeline: ({ tenantId, pipelineId }, client) =>
      client.$executeRaw`SELECT pg_advisory_xact_lock(hashtext(${`pipeline:${tenantId}:${pipelineId}`}))`,

    /** One execution by tenant AND id (the only way to load one). */
    findExecution: ({ tenantId, id }, client = db) =>
      executions.findExecution({ tenantId, executionId: id }, client),

    /** The pipeline of an execution with the state of its parents (the effective state is computed from it), by the whole chain. */
    findPipelineContext: ({ tenantId, workspaceId, repositoryId, pipelineId }, client = db) =>
      client.pipeline.findFirst({
        where: { tenantId, workspaceId, repositoryId, id: pipelineId },
        select: {
          id: true,
          enabled: true,
          deletedAt: true,
          workspace: { select: { id: true, status: true } },
          repository: { select: { id: true, status: true, enabled: true } },
          tenant: { select: { status: true } },
        },
      }),

    /** The immutable snapshot an execution ran (or will run) with, by tenant, pipeline and version id. */
    findSnapshot: ({ tenantId, pipelineId, id }, client = db) =>
      client.pipelineConfigVersion.findFirst({
        where: { tenantId, pipelineId, id },
        select: { id: true, version: true, configHash: true, config: true },
      }),

    findExecutionByKey: ({ tenantId, pipelineId, idempotencyKey }, client = db) =>
      client.execution.findFirst({ where: { tenantId, pipelineId, idempotencyKey } }),

    /**
     * How many retries precede an execution: the length of its `retry_of` chain (0 for an original). The walk is bounded by
     * `limit + 1` hops and every hop is tenant and pipeline scoped.
     * @returns {Promise<number>}
     */
    async retryDepth({ tenantId, pipelineId, executionId, limit }, client = db) {
      let depth = 0;
      let current = await client.execution.findFirst({
        where: { tenantId, pipelineId, id: executionId },
        select: { retryOfExecutionId: true },
      });
      while (current?.retryOfExecutionId && depth <= limit) {
        depth += 1;
        current = await client.execution.findFirst({
          where: { tenantId, pipelineId, id: current.retryOfExecutionId },
          select: { retryOfExecutionId: true },
        });
      }
      return depth;
    },

    countExecutions: ({ tenantId, pipelineId, statuses, concurrencyGroup }, client = db) =>
      client.execution.count({
        where: {
          tenantId,
          pipelineId,
          status: { in: statuses },
          ...(concurrencyGroup ? { concurrencyGroup } : {}),
        },
      }),

    /** Inserts an execution row of a tenant's pipeline (the caller supplies the whole snapshot copy). */
    createExecution: ({ tenantId, workspaceId, repositoryId, pipelineId, ...data }, client = db) =>
      client.execution.create({
        data: { tenantId, workspaceId, repositoryId, pipelineId, ...data },
      }),

    /**
     * The queued requests of one concurrency group, cancelled through the shared cancel (the unit is given back once, in the
     * caller's transaction). Returns exactly what was cancelled.
     */
    async cancelQueuedInGroup({ tenantId, pipelineId, concurrencyGroup, reason }, client = db) {
      const rows = await client.execution.findMany({
        where: { tenantId, pipelineId, status: "queued", concurrencyGroup },
        select: { id: true },
      });
      const cancelled = [];
      for (const row of rows) {
        const done = await cancellation.cancelQueued(
          { tenantId, executionId: row.id, reason },
          client,
        );
        if (done.cancelled) cancelled.push({ ...row, quotaReleased: done.quotaReleased });
      }
      return cancelled;
    },

    /** The shared `queued -> cancelled` (CAS + quota release once) for ONE execution of this tenant. */
    cancelQueued: (input, client) => cancellation.cancelQueued(input, client),

    /** The shared cancel REQUEST on a preparing/running execution (the four cancel columns, once). */
    requestCancel: (input, client) => cancellation.requestCancel(input, client),

    /** Appends a non-transition history row (`retry_requested`) for an execution of this tenant. */
    recordEvent: (input, client) => executions.recordEvent(input, client),

    // ---- read side (part G). Every function carries the trusted tenant; children are also bound to their execution.

    /** Id and workspace of an execution of this tenant (the scope resolver's and the denial audit's lookup). */
    findRef: ({ tenantId, id }, client = db) =>
      client.execution.findFirst({
        where: { tenantId, id },
        select: { id: true, workspaceId: true, pipelineId: true },
      }),

    /** One keyset page of execution ids (see `createExecutionReadRepository`). */
    listPage: (input, client = db) => reads.listPage(input, client),

    /** Count of the same filtered, tenant-scoped, accessible-workspace set as `listPage` (numbered pages only). */
    countList: (input, client = db) => reads.countList(input, client),

    /** The rows of one page, tenant scoped and restricted to the accessible workspaces. */
    findExecutions: ({ tenantId, workspaceIds, ids }, client = db) =>
      client.execution.findMany({
        where: { tenantId, workspaceId: { in: workspaceIds }, id: { in: ids } },
        select: EXECUTION_COLUMNS,
      }),

    /** One execution by tenant, workspace (the scope the caller was authorized in) and id. */
    findExecutionDetail: ({ tenantId, workspaceId, id }, client = db) =>
      client.execution.findFirst({
        where: { tenantId, workspaceId, id },
        select: { ...EXECUTION_COLUMNS, ...DETAIL_COLUMNS },
      }),

    /** Pipeline names of a set of pipelines of this tenant (labels only). */
    async findPipelineNames({ tenantId, pipelineIds }, client = db) {
      if (pipelineIds.length === 0) return new Map();
      const rows = await client.pipeline.findMany({
        where: { tenantId, id: { in: pipelineIds } },
        select: { id: true, name: true },
      });
      return new Map(rows.map((r) => [r.id, r.name]));
    },

    /** Repository full names of a set of repositories of this tenant (labels only). */
    async findRepositoryNames({ tenantId, repositoryIds }, client = db) {
      if (repositoryIds.length === 0) return new Map();
      const rows = await client.repository.findMany({
        where: { tenantId, id: { in: repositoryIds } },
        select: { id: true, fullName: true },
      });
      return new Map(rows.map((r) => [r.id, r.fullName]));
    },

    /** Display names of members of this tenant. */
    async findMemberNames({ tenantId, userIds }, client = db) {
      if (userIds.length === 0) return new Map();
      const rows = await client.tenantMembership.findMany({
        where: { tenantId, userId: { in: userIds } },
        select: { user: { select: { id: true, name: true } } },
      });
      return new Map(rows.map((r) => [r.user.id, r.user.name]));
    },

    /** Task status counts per execution for a page of executions (tenant scoped). */
    async countTasksByStatus({ tenantId, executionIds }, client = db) {
      if (executionIds.length === 0) return [];
      return client.scanTask.groupBy({
        by: ["executionId", "status"],
        where: { tenantId, executionId: { in: executionIds } },
        _count: { _all: true },
      });
    },

    /** The tasks of one execution with their result summary, in catalog order (tenant and execution scoped). */
    findTasks: ({ tenantId, executionId }, client = db) =>
      client.scanTask.findMany({
        where: { tenantId, executionId },
        orderBy: { ordinal: "asc" },
        select: {
          id: true,
          scanType: true,
          status: true,
          statusReason: true,
          attempt: true,
          maxAttempts: true,
          engineId: true,
          engineProfile: true,
          startedAt: true,
          finishedAt: true,
          results: {
            where: { tenantId, executionId },
            orderBy: { attempt: "desc" },
            take: 1,
            select: { itemCount: true, severityCounts: true, truncated: true, completeness: true },
          },
        },
      }),

    /** The scan types the snapshot enabled (ids only; the configuration body never leaves the repository layer). */
    async findEnabledScanTypes({ tenantId, pipelineId, configVersionId }, client = db) {
      const version = await client.pipelineConfigVersion.findFirst({
        where: { tenantId, pipelineId, id: configVersionId },
        select: { config: true },
      });
      const scans = version?.config?.scans;
      return scans && typeof scans === "object"
        ? Object.entries(scans)
            .filter(([, value]) => value?.enabled === true)
            .map(([type]) => type)
        : [];
    },

    /** The history of one execution, oldest first, strictly after `afterSeq` (one extra row tells whether more follow). */
    findEvents: ({ tenantId, workspaceId, executionId, afterSeq, limit }, client = db) =>
      client.executionEvent.findMany({
        where: { tenantId, workspaceId, executionId, seq: { gt: afterSeq } },
        orderBy: { seq: "asc" },
        take: limit + 1,
        select: {
          seq: true,
          at: true,
          type: true,
          fromStatus: true,
          toStatus: true,
          reason: true,
          actorType: true,
        },
      }),
  });
}
