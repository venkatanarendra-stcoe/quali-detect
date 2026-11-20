import { withTransaction } from "../transaction.js";

/** Defaults of the retention periods (SPEC ER-17, Confirmed PT Q18): logs and raw outputs 90 days, metadata 13 months. */
export const RETENTION_DEFAULTS = Object.freeze({
  logRetentionDays: 90,
  artifactRetentionDays: 90,
  metadataRetentionMonths: 13,
});

/** The fixed name of the changed-paths artifact (scan engines D-7); the workers module `changed-paths.js` holds the same constant (asserted by the suite). */
export const CHANGED_PATHS_ARTIFACT_NAME = "changed-paths.json";

const positiveInt = (value, name, max) => {
  if (!Number.isInteger(value) || value < 1 || value > max)
    throw new TypeError(`${name} must be an integer between 1 and ${max}`);
  return value;
};

/**
 * Retention purge of the execution module (docs/modules/executions/SPEC.md ER-17, §17.ac). PLATFORM-LEVEL: it looks across
 * tenants on purpose and is called only from the platform (scheduler) worker, never from an API request or a tenant message.
 * It never touches a row that is not expired and never touches a non-terminal execution; the clock is the database's `now()`;
 * every pass is batch-limited (`FOR UPDATE SKIP LOCKED`, so concurrent purges take different rows) and idempotent (a repeat
 * finds nothing more). It returns COUNTS only, which the caller logs and audits; it never returns or logs row content.
 *
 * - logs (`execution_logs`): older than the log retention, of TERMINAL executions; their counters go once no line is left;
 * - artifacts (`execution_artifacts`): older than the artifact retention (raw outputs, 90 days), terminal executions;
 * - orphan changed-paths artifacts (scan engines, owner decision 2026-11-20): the artifact is written BEFORE the decision transaction
 *   (SPEC 5.9 SE-22), so a rolled-back or never-committed decision can leave one behind. Of a TERMINAL execution (no decision can
 *   commit any more) an artifact named `changed-paths.json` that no committed decision of that execution references is removed at once,
 *   whatever its age; it is never read without a committed decision (the reader goes through the decision row);
 * - metadata: terminal executions finished more than the metadata retention (13 months) ago and no longer the original of a
 *   retry, with all their children, one execution per transaction. Optional (`metadataRetentionMonths: null` skips it).
 * @param {{ db: any }} deps Prisma client
 */
export function createExecutionRetentionRepository({ db }) {
  /** Deletes up to `batchSize` rows per pass, at most `maxBatches` passes; returns the number deleted. */
  async function inBatches(run, batchSize, maxBatches) {
    let total = 0;
    for (let i = 0; i < maxBatches; i += 1) {
      const n = await run();
      total += n;
      if (n < batchSize) break;
    }
    return total;
  }

  return Object.freeze({
    /**
     * One purge run.
     * @param {{ logRetentionDays?: number, artifactRetentionDays?: number, metadataRetentionMonths?: number | null, batchSize?: number, maxBatches?: number }} [options]
     * @param {any} [client]
     * @returns {Promise<{ logs: number, logCounters: number, artifacts: number, orphanChangedPaths: number, executions: number, executionsSkipped: number }>}
     */
    async purgeExpired(options = {}, client = db) {
      const logDays = positiveInt(
        options.logRetentionDays ?? RETENTION_DEFAULTS.logRetentionDays,
        "logRetentionDays",
        3650,
      );
      const artifactDays = positiveInt(
        options.artifactRetentionDays ?? RETENTION_DEFAULTS.artifactRetentionDays,
        "artifactRetentionDays",
        3650,
      );
      const months =
        options.metadataRetentionMonths === null
          ? null
          : positiveInt(
              options.metadataRetentionMonths ?? RETENTION_DEFAULTS.metadataRetentionMonths,
              "metadataRetentionMonths",
              600,
            );
      const batchSize = positiveInt(options.batchSize ?? 500, "batchSize", 5000);
      const maxBatches = positiveInt(options.maxBatches ?? 20, "maxBatches", 1000);

      const logs = await inBatches(
        () =>
          client.$executeRaw`
            WITH doomed AS (
              SELECT l.id FROM execution_logs l
              JOIN executions e ON e.tenant_id = l.tenant_id AND e.id = l.execution_id
              WHERE l.at < now() - make_interval(days => ${logDays}::int) AND execution_status_is_terminal(e.status)
              ORDER BY l.at, l.id LIMIT ${batchSize}::int FOR UPDATE OF l SKIP LOCKED)
            DELETE FROM execution_logs l USING doomed WHERE l.id = doomed.id`,
        batchSize,
        maxBatches,
      );
      // counters of an execution whose lines are all gone (and that are themselves older than the retention)
      const taskCounters = await inBatches(
        () =>
          client.$executeRaw`
            DELETE FROM execution_task_log_counters c WHERE (c.tenant_id, c.scan_task_id) IN (
              SELECT k.tenant_id, k.scan_task_id FROM execution_task_log_counters k
              WHERE k.updated_at < now() - make_interval(days => ${logDays}::int)
                AND NOT EXISTS (SELECT 1 FROM execution_logs l WHERE l.tenant_id = k.tenant_id AND l.execution_id = k.execution_id)
              LIMIT ${batchSize}::int)`,
        batchSize,
        maxBatches,
      );
      const execCounters = await inBatches(
        () =>
          client.$executeRaw`
            DELETE FROM execution_log_counters c WHERE (c.tenant_id, c.execution_id) IN (
              SELECT k.tenant_id, k.execution_id FROM execution_log_counters k
              WHERE k.updated_at < now() - make_interval(days => ${logDays}::int)
                AND NOT EXISTS (SELECT 1 FROM execution_logs l WHERE l.tenant_id = k.tenant_id AND l.execution_id = k.execution_id)
                AND NOT EXISTS (SELECT 1 FROM execution_task_log_counters t WHERE t.tenant_id = k.tenant_id AND t.execution_id = k.execution_id)
              LIMIT ${batchSize}::int)`,
        batchSize,
        maxBatches,
      );
      const artifacts = await inBatches(
        () =>
          client.$executeRaw`
            WITH doomed AS (
              SELECT a.id FROM execution_artifacts a
              JOIN executions e ON e.tenant_id = a.tenant_id AND e.id = a.execution_id
              WHERE a.created_at < now() - make_interval(days => ${artifactDays}::int) AND execution_status_is_terminal(e.status)
              ORDER BY a.created_at, a.id LIMIT ${batchSize}::int FOR UPDATE OF a SKIP LOCKED)
            DELETE FROM execution_artifacts a USING doomed WHERE a.id = doomed.id`,
        batchSize,
        maxBatches,
      );

      const orphanChangedPaths = await inBatches(
        () =>
          client.$executeRaw`
            WITH doomed AS (
              SELECT a.id FROM execution_artifacts a
              JOIN executions e ON e.tenant_id = a.tenant_id AND e.id = a.execution_id
              WHERE a.name = ${CHANGED_PATHS_ARTIFACT_NAME} AND execution_status_is_terminal(e.status)
                AND NOT EXISTS (
                  SELECT 1 FROM scan_decisions d
                  WHERE d.tenant_id = a.tenant_id AND d.execution_id = a.execution_id
                    AND d.changed_paths_status = 'complete' AND d.changed_paths_ref = a.name)
              ORDER BY a.created_at, a.id LIMIT ${batchSize}::int FOR UPDATE OF a SKIP LOCKED)
            DELETE FROM execution_artifacts a USING doomed WHERE a.id = doomed.id`,
        batchSize,
        maxBatches,
      );

      let executions = 0;
      let executionsSkipped = 0;
      if (months !== null) {
        for (let i = 0; i < maxBatches; i += 1) {
          const picked = await client.$queryRaw`
            SELECT e.tenant_id AS "tenantId", e.id FROM executions e
            WHERE execution_status_is_terminal(e.status) AND COALESCE(e.finished_at, e.requested_at) < now() - make_interval(months => ${months}::int)
              AND NOT EXISTS (SELECT 1 FROM executions r WHERE r.tenant_id = e.tenant_id AND r.retry_of_execution_id = e.id)
            ORDER BY COALESCE(e.finished_at, e.requested_at), e.id LIMIT ${batchSize}::int`;
          let progressed = 0;
          for (const { tenantId, id } of picked) {
            try {
              const done = await withTransaction(client, async (tx) => {
                const [locked] = await tx.$queryRaw`
                  SELECT id FROM executions
                  WHERE tenant_id = ${tenantId}::uuid AND id = ${id}::uuid AND execution_status_is_terminal(status)
                    AND COALESCE(finished_at, requested_at) < now() - make_interval(months => ${months}::int)
                    AND NOT EXISTS (SELECT 1 FROM executions r WHERE r.tenant_id = ${tenantId}::uuid AND r.retry_of_execution_id = ${id}::uuid)
                  FOR UPDATE SKIP LOCKED`;
                if (!locked) return false;
                const scope = { tenantId, id };
                await tx.$executeRaw`DELETE FROM scan_result_item_details WHERE tenant_id = ${scope.tenantId}::uuid AND execution_id = ${scope.id}::uuid`;
                await tx.$executeRaw`DELETE FROM scan_result_items WHERE tenant_id = ${scope.tenantId}::uuid AND execution_id = ${scope.id}::uuid`;
                await tx.$executeRaw`DELETE FROM scan_results WHERE tenant_id = ${scope.tenantId}::uuid AND execution_id = ${scope.id}::uuid`;
                await tx.$executeRaw`DELETE FROM scan_tool_runs WHERE tenant_id = ${scope.tenantId}::uuid AND execution_id = ${scope.id}::uuid`;
                await tx.$executeRaw`DELETE FROM scan_task_attempts WHERE tenant_id = ${scope.tenantId}::uuid AND execution_id = ${scope.id}::uuid`;
                await tx.$executeRaw`DELETE FROM execution_logs WHERE tenant_id = ${scope.tenantId}::uuid AND execution_id = ${scope.id}::uuid`;
                await tx.$executeRaw`DELETE FROM execution_task_log_counters WHERE tenant_id = ${scope.tenantId}::uuid AND execution_id = ${scope.id}::uuid`;
                await tx.$executeRaw`DELETE FROM execution_log_counters WHERE tenant_id = ${scope.tenantId}::uuid AND execution_id = ${scope.id}::uuid`;
                await tx.$executeRaw`DELETE FROM execution_artifacts WHERE tenant_id = ${scope.tenantId}::uuid AND execution_id = ${scope.id}::uuid`;
                await tx.$executeRaw`DELETE FROM scan_decisions WHERE tenant_id = ${scope.tenantId}::uuid AND execution_id = ${scope.id}::uuid`;
                await tx.$executeRaw`DELETE FROM scan_tasks WHERE tenant_id = ${scope.tenantId}::uuid AND execution_id = ${scope.id}::uuid`;
                await tx.$executeRaw`DELETE FROM execution_events WHERE tenant_id = ${scope.tenantId}::uuid AND execution_id = ${scope.id}::uuid`;
                await tx.$executeRaw`DELETE FROM executions WHERE tenant_id = ${scope.tenantId}::uuid AND id = ${scope.id}::uuid`;
                return true;
              });
              if (done) {
                executions += 1;
                progressed += 1;
              }
            } catch {
              // a row still referenced elsewhere (a future foreign key) stays; the run goes on and reports the count
              executionsSkipped += 1;
            }
          }
          if (progressed === 0 || picked.length < batchSize) break;
        }
      }
      return {
        logs,
        logCounters: taskCounters + execCounters,
        artifacts,
        orphanChangedPaths,
        executions,
        executionsSkipped,
      };
    },
  });
}
