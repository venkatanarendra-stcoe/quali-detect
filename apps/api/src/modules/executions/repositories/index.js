import { createExecutionCancellation, createExecutionRepository } from "@qmentisai/db";

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
  });
}
