/**
 * Data access of the pipeline trigger router (docs/modules/pipelines-triggers/SPEC.md §6.2, §7). EVERY function carries the
 * trusted `tenantId` in its `where` (the tenant of the message is only trusted after the repository row proves it), and
 * workspace and repository ids are added wherever the caller knows them, so nothing is read or changed by id alone. `client`
 * is the Prisma client or a transaction client. Prisma stays inside this file.
 * @param {{ db: any }} deps
 */
export function createRouterRepository({ db }) {
  return Object.freeze({
    /**
     * The repository of an event with the state of its workspace and tenant: the single source for the lifecycle gates.
     * @param {{ tenantId: string, id: string }} input
     */
    findRepositoryState: ({ tenantId, id }, client = db) =>
      client.repository.findFirst({
        where: { tenantId, id },
        select: {
          id: true,
          workspaceId: true,
          status: true,
          enabled: true,
          defaultBranch: true,
          workspace: { select: { status: true } },
          tenant: { select: { status: true } },
        },
      }),

    /** The normalized event row of a delivery (unique per tenant, delivery id and kind). */
    findScmEvent: ({ tenantId, deliveryId, kind }, client = db) =>
      client.scmEvent.findFirst({
        where: { tenantId, deliveryId, kind },
        select: { id: true, repositoryId: true, createdAt: true },
      }),

    /**
     * Non-deleted pipelines of ONE repository (never by external repository id) with their current configuration version,
     * disabled ones included (a match on a disabled pipeline is recorded as `pipeline_disabled`). Oldest first, bounded.
     */
    listRoutingPipelines: ({ tenantId, workspaceId, repositoryId, limit }, client = db) =>
      client.pipeline.findMany({
        where: { tenantId, workspaceId, repositoryId, deletedAt: null },
        orderBy: [{ createdAt: "asc" }, { id: "asc" }],
        take: limit,
        select: {
          id: true,
          name: true,
          enabled: true,
          currentVersionId: true,
          currentConfig: {
            select: {
              id: true,
              version: true,
              schemaVersion: true,
              config: true,
              configHash: true,
            },
          },
        },
      }),

    /** Per-pipeline advisory lock (transaction scoped; the same key as the pipelines API, so a manual run and a router cannot interleave). */
    lockPipeline: ({ tenantId, pipelineId }, client) =>
      client.$executeRaw`SELECT pg_advisory_xact_lock(hashtext(${`pipeline:${tenantId}:${pipelineId}`}))`,

    /** The request this SCM event already created for the pipeline, if any (idempotency by `(scm event, pipeline)`). */
    findExecutionByScmEvent: ({ tenantId, pipelineId, scmEventId }, client = db) =>
      client.execution.findFirst({
        where: { tenantId, pipelineId, scmEventId },
        select: { id: true, status: true },
      }),

    /** The latest request of a pipeline with its configuration, for the scan-kind history (first run, changed configuration). */
    findLatestExecution: ({ tenantId, pipelineId }, client = db) =>
      client.execution.findFirst({
        where: { tenantId, pipelineId },
        orderBy: { requestedAt: "desc" },
        select: { id: true, version: { select: { config: true } } },
      }),

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
     * Out-of-order hint (SPEC §6.2): a request of the same group whose base commit is the incoming `after` was made for a LATER
     * push, so the incoming push is stale.
     */
    findNewerInGroup: ({ tenantId, pipelineId, concurrencyGroup, baseSha }, client = db) =>
      client.execution.findFirst({
        where: { tenantId, pipelineId, concurrencyGroup, baseSha },
        select: { id: true },
      }),

    /**
     * Cancels the queued requests of one concurrency group with a conditional update per row and returns exactly what was
     * cancelled, with the quota to give back.
     * @returns {Promise<Array<{ id: string, quotaPeriod: string | null, quotaConsumed: number }>>}
     */
    async cancelQueued({ tenantId, pipelineId, concurrencyGroup, reason }, client = db) {
      const rows = await client.execution.findMany({
        where: { tenantId, pipelineId, status: "queued", concurrencyGroup },
        select: { id: true, quotaPeriod: true, quotaConsumed: true },
      });
      const cancelled = [];
      for (const row of rows) {
        const done = await client.execution.updateMany({
          where: { id: row.id, tenantId, pipelineId, status: "queued" },
          data: {
            status: "cancelled",
            statusReason: reason,
            // the caller gives the unit back in this transaction; recording it here keeps "released once" visible on the row
            ...(row.quotaConsumed > 0 ? { quotaReleasedAt: new Date() } : {}),
          },
        });
        if (done.count === 1) cancelled.push(row);
      }
      return cancelled;
    },

    /**
     * Cancels the still-`queued` requests of ONE pull request of ONE pipeline (a pull request closed on the SCM side,
     * SPEC §5.4). Scoped by tenant, workspace, repository and pipeline plus the pull request number; running, terminal and
     * every other request (other numbers, push, schedule, manual) are never selected, and the conditional update per row
     * keeps a row that started in the meantime. Only requests caused by an SCM event received at or before `receivedUntil`
     * (the closed event's own receipt time) are cancelled, so a redelivery of an old closed message never cancels a run
     * requested after a reopen. Returns exactly what was cancelled, with the quota to give back.
     * @returns {Promise<Array<{ id: string, triggerKey: string, quotaPeriod: string | null, quotaConsumed: number }>>}
     */
    async cancelQueuedForPullRequest(
      { tenantId, workspaceId, repositoryId, pipelineId, pullRequestNumber, receivedUntil, reason },
      client = db,
    ) {
      const rows = await client.execution.findMany({
        where: {
          tenantId,
          workspaceId,
          repositoryId,
          pipelineId,
          triggerType: "pull_request",
          pullRequestNumber,
          status: "queued",
        },
        orderBy: [{ requestedAt: "asc" }, { id: "asc" }],
        select: {
          id: true,
          triggerKey: true,
          scmEventId: true,
          quotaPeriod: true,
          quotaConsumed: true,
        },
      });
      const events = rows.length
        ? await client.scmEvent.findMany({
            where: {
              tenantId,
              repositoryId,
              id: { in: rows.map((row) => row.scmEventId).filter(Boolean) },
              createdAt: { lte: receivedUntil },
            },
            select: { id: true },
          })
        : [];
      const early = new Set(events.map((event) => event.id));
      const cancelled = [];
      for (const row of rows) {
        if (!early.has(row.scmEventId)) continue;
        const done = await client.execution.updateMany({
          where: { id: row.id, tenantId, workspaceId, repositoryId, pipelineId, status: "queued" },
          data: {
            status: "cancelled",
            statusReason: reason,
            // the caller gives the unit back in this transaction; recording it here keeps "released once" visible on the row
            ...(row.quotaConsumed > 0 ? { quotaReleasedAt: new Date() } : {}),
          },
        });
        if (done.count === 1) cancelled.push(row);
      }
      return cancelled;
    },

    createExecution: ({ tenantId, workspaceId, repositoryId, pipelineId, ...data }, client = db) =>
      client.execution.create({
        data: { tenantId, workspaceId, repositoryId, pipelineId, ...data },
      }),

    /** Inserts a policy-skip decision (`sourceType` and its matching key are required, the database CHECK refuses a mismatch); a redelivery, a repeated tick or a replay is absorbed by the unique key of the source type. @returns {Promise<number>} rows written (0 or 1) */
    async createDecision(
      { tenantId, workspaceId, repositoryId, pipelineId, ...data },
      client = db,
    ) {
      const done = await client.pipelineTriggerDecision.createMany({
        data: [{ tenantId, workspaceId, repositoryId, pipelineId, ...data }],
        skipDuplicates: true,
      });
      return done.count;
    },

    /** Whether the quota/entitlement block of this pipeline and reason was already audited since `since` (one entry per day). */
    async hasBlockedAuditSince({ tenantId, pipelineId, action, reason, since }, client = db) {
      const row = await client.auditLog.findFirst({
        where: {
          tenantId,
          action,
          targetType: "pipeline",
          targetId: pipelineId,
          createdAt: { gte: since },
          metadata: { path: ["reason"], equals: reason },
        },
        select: { id: true },
      });
      return Boolean(row);
    },
  });
}
