/**
 * Data access of the schedule handler (docs/modules/pipelines-triggers/SPEC.md §6.4, §7.2). Two kinds of function:
 * - the PLATFORM scans (`peekDue`, `peekUnscheduled`) look across tenants on purpose, like the session purge: they return only
 *   the identifiers of one trigger row; nothing else is read or written from them;
 * - every other function carries the trusted `tenantId` (taken from the claimed trigger row, never from a message) together
 *   with the workspace, repository and pipeline ids the caller knows, so nothing is read or changed by id alone.
 * `client` is the Prisma client or a transaction client. Prisma stays inside this file.
 * @param {{ db: any }} deps
 */
export function createScheduleRepository({ db }) {
  const iso = (date) => date.toISOString();
  return Object.freeze({
    /**
     * The next due schedule trigger (`next_fire_at <= now`, ordered by it) that was not tried in this run: platform scan on the
     * partial due-schedule index, no lock (the claim takes it). `excludeTenantIds` are tenants that used their per-tick share.
     * @param {{ now: Date, excludeIds: string[], excludeTenantIds: string[] }} input
     * @returns {Promise<{ id: string, tenantId: string, workspaceId: string, repositoryId: string, pipelineId: string } | null>}
     */
    async peekDue({ now, excludeIds, excludeTenantIds }, client = db) {
      const rows = await client.$queryRaw`
        SELECT t.id, t.tenant_id AS "tenantId", t.workspace_id AS "workspaceId", t.repository_id AS "repositoryId", t.pipeline_id AS "pipelineId"
        FROM pipeline_triggers t
        WHERE t.type = 'schedule' AND t.enabled AND t.next_fire_at <= ${iso(now)}::timestamptz
          AND t.id <> ALL(${excludeIds}::uuid[]) AND t.tenant_id <> ALL(${excludeTenantIds}::uuid[])
        ORDER BY t.next_fire_at, t.id
        LIMIT 1`;
      return rows[0] ?? null;
    },

    /**
     * An enabled schedule trigger of an enabled, live pipeline that has no planned time yet (created before the scheduler
     * existed, or its pipeline was enabled outside the API): the handler plans it from now. Platform scan, identifiers only.
     * @param {{ excludeIds: string[] }} input
     */
    async peekUnscheduled({ excludeIds }, client = db) {
      const rows = await client.$queryRaw`
        SELECT t.id, t.tenant_id AS "tenantId", t.workspace_id AS "workspaceId", t.repository_id AS "repositoryId", t.pipeline_id AS "pipelineId"
        FROM pipeline_triggers t
        JOIN pipelines p ON p.tenant_id = t.tenant_id AND p.id = t.pipeline_id
        WHERE t.type = 'schedule' AND t.enabled AND t.next_fire_at IS NULL AND p.enabled AND p.deleted_at IS NULL
          AND t.id <> ALL(${excludeIds}::uuid[])
        ORDER BY t.created_at, t.id
        LIMIT 1`;
      return rows[0] ?? null;
    },

    /**
     * Claims the trigger row (`FOR UPDATE SKIP LOCKED`, scoped by tenant, workspace, repository and pipeline) if it is still
     * due: another handler that holds or has already advanced it makes this return null. The caller holds the pipeline lock.
     * @param {{ tenantId: string, workspaceId: string, repositoryId: string, pipelineId: string, id: string, now: Date }} input
     */
    async claimDue({ tenantId, workspaceId, repositoryId, pipelineId, id, now }, client) {
      const rows = await client.$queryRaw`
        SELECT id, tenant_id AS "tenantId", workspace_id AS "workspaceId", repository_id AS "repositoryId", pipeline_id AS "pipelineId",
               trigger_key AS "triggerKey", cron, timezone, next_fire_at AS "nextFireAt", missed_policy AS "missedPolicy",
               jitter_offset_seconds AS "jitterOffsetSeconds"
        FROM pipeline_triggers
        WHERE tenant_id = ${tenantId}::uuid AND workspace_id = ${workspaceId}::uuid AND repository_id = ${repositoryId}::uuid
          AND pipeline_id = ${pipelineId}::uuid AND id = ${id}::uuid
          AND type = 'schedule' AND enabled AND next_fire_at <= ${iso(now)}::timestamptz
        FOR UPDATE SKIP LOCKED`;
      return rows[0] ?? null;
    },

    /** Claims an unplanned trigger row (same scoping and locking as `claimDue`). */
    async claimUnscheduled({ tenantId, workspaceId, repositoryId, pipelineId, id }, client) {
      const rows = await client.$queryRaw`
        SELECT id, tenant_id AS "tenantId", workspace_id AS "workspaceId", repository_id AS "repositoryId", pipeline_id AS "pipelineId",
               trigger_key AS "triggerKey", cron, timezone, jitter_offset_seconds AS "jitterOffsetSeconds"
        FROM pipeline_triggers
        WHERE tenant_id = ${tenantId}::uuid AND workspace_id = ${workspaceId}::uuid AND repository_id = ${repositoryId}::uuid
          AND pipeline_id = ${pipelineId}::uuid AND id = ${id}::uuid
          AND type = 'schedule' AND enabled AND next_fire_at IS NULL
        FOR UPDATE SKIP LOCKED`;
      return rows[0] ?? null;
    },

    /**
     * The pipeline (live or deleted) with its current configuration version, found only inside its tenant, workspace and
     * repository, so a trigger row can never reach another tenant's or workspace's pipeline.
     */
    findPipelineForFire: ({ tenantId, workspaceId, repositoryId, pipelineId }, client = db) =>
      client.pipeline.findFirst({
        where: { tenantId, workspaceId, repositoryId, id: pipelineId },
        select: {
          id: true,
          enabled: true,
          deletedAt: true,
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

    /** The repository inside its tenant AND workspace, with the state of its workspace and tenant: the source of the fire-time gates. */
    findRepositoryForFire: ({ tenantId, workspaceId, repositoryId }, client = db) =>
      client.repository.findFirst({
        where: { tenantId, workspaceId, id: repositoryId },
        select: {
          id: true,
          status: true,
          enabled: true,
          defaultBranch: true,
          workspace: { select: { status: true } },
          tenant: { select: { status: true } },
        },
      }),

    /**
     * Records that a due slot was skipped by policy (SPEC §7.8: source type `schedule_slot`, keyed by the nominal UTC slot).
     * The scope fields come from the claimed trigger row and the composite foreign key makes the database refuse a pipeline of
     * another tenant, workspace or repository; a repeat for the same (tenant, pipeline, trigger, slot) is absorbed by the
     * partial unique index. @returns {Promise<number>} rows written (0 or 1)
     */
    async createDecision(
      {
        tenantId,
        workspaceId,
        repositoryId,
        pipelineId,
        triggerKey,
        scheduleSlot,
        reason,
        refName,
        correlationId,
      },
      client,
    ) {
      const done = await client.pipelineTriggerDecision.createMany({
        data: [
          {
            tenantId,
            workspaceId,
            repositoryId,
            pipelineId,
            triggerType: "schedule",
            triggerKey,
            sourceType: "schedule_slot",
            scheduleSlot,
            reason,
            refType: "branch",
            refName,
            correlationId: correlationId ?? null,
          },
        ],
        skipDuplicates: true,
      });
      return done.count;
    },

    /** The request this slot already created for the pipeline, if any (idempotency by `(tenant, pipeline, slot)`). */
    findExecutionBySlot: ({ tenantId, pipelineId, scheduleSlot }, client = db) =>
      client.execution.findFirst({
        where: { tenantId, pipelineId, scheduleSlot },
        select: { id: true, status: true },
      }),

    /**
     * Writes the trigger's schedule state (planned time, last handled slot, activation, projection repair), scoped by
     * tenant, pipeline and id. @returns {Promise<number>} rows changed
     */
    async updateTrigger({ tenantId, pipelineId, id, data }, client = db) {
      const done = await client.pipelineTrigger.updateMany({
        where: { id, tenantId, pipelineId, type: "schedule" },
        data,
      });
      return done.count;
    },
  });
}
