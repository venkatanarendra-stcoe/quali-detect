import { REPORT_DEFAULT_TIME_ZONE } from "@qmentisai/shared";
import { cnt, day, iso, readTx, uuid, OPEN_SQL } from "./tx.js";

/**
 * Posture reads (SPEC 6.1 P-1 to P-10) and the freshness of the rollups. P-1 to P-9 come from ONE grouped query over `report_findings_v`
 * (at most 12 statuses x 5 severities x 3 types rows come back, the mapper derives every tile from them); the as-of posture comes from the
 * daily rollup of a past tenant-local day.
 * @param {any} db the read client
 */
export function buildPostureMethods(db) {
  return {
    async getTenantSettings({ tenantId }) {
      uuid("tenantId", tenantId);
      const rows = await readTx(
        db,
        (tx) => tx.$queryRaw`
          SELECT reporting_timezone AS "timeZone" FROM report_tenant_settings_v WHERE tenant_id = ${tenantId}::uuid`,
      );
      return { timeZone: rows[0]?.timeZone ?? REPORT_DEFAULT_TIME_ZONE };
    },

    async getRollupFreshness({ tenantId }) {
      uuid("tenantId", tenantId);
      const rows = await readTx(
        db,
        (tx) => tx.$queryRaw`
          SELECT max(finished_at) FILTER (WHERE status = 'succeeded') AS "lastSuccessAt",
                 (min(day) FILTER (WHERE status = 'succeeded'))::text AS "firstDay",
                 COALESCE(bool_or(status = 'running' AND mode = 'backfill' AND started_at > now() - interval '6 hours'), false) AS recomputing
          FROM report_rollup_runs WHERE tenant_id = ${tenantId}::uuid`,
      );
      const r = rows[0] ?? {};
      return {
        lastSuccessAt: r.lastSuccessAt ? new Date(r.lastSuccessAt) : null,
        firstDay: r.firstDay ?? null,
        recomputing: r.recomputing === true,
      };
    },

    async getPosture({ tenantId, workspaceId, now, includePipelines }) {
      uuid("tenantId", tenantId);
      uuid("workspaceId", workspaceId);
      const nowIso = iso(now);
      const soon = iso(new Date(now.getTime() + 30 * 86_400_000));
      const since = iso(new Date(now.getTime() - 86_400_000));
      const windowStart = iso(new Date(now.getTime() - 90 * 86_400_000));
      return readTx(db, async (tx) => {
        const groups = await tx.$queryRaw`
          SELECT f.status::text AS status, f.severity::text AS severity, f.scan_type::text AS "scanType",
                 count(*)::int AS n,
                 (count(*) FILTER (WHERE f.exception_pending))::int AS "pendingExceptions",
                 (count(*) FILTER (WHERE f.exception_expires_at IS NOT NULL AND f.exception_expires_at <= ${soon}::timestamptz
                                     AND f.status IN ('accepted_risk', 'suppressed')))::int AS "expiring",
                 (count(*) FILTER (WHERE f.first_detected_at >= ${since}::timestamptz))::int AS "newLast24Hours",
                 (count(*) FILTER (WHERE f.sla_due_at IS NOT NULL AND f.sla_due_at < ${nowIso}::timestamptz
                                     AND f.status IN (${OPEN_SQL})))::int AS "slaBreached"
          FROM report_findings_v f
          WHERE f.tenant_id = ${tenantId}::uuid AND f.workspace_id = ${workspaceId}::uuid
          GROUP BY f.status, f.severity, f.scan_type`;
        let pipelines = null;
        if (includePipelines) {
          // P-10: the latest FINISHED outcome of each live pipeline that ran in the last 90 days (the views carry no "enabled" flag)
          const p = await tx.$queryRaw`
            SELECT count(*)::int AS total, (count(*) FILTER (WHERE x.status = 'succeeded'))::int AS healthy
            FROM (
              SELECT DISTINCT ON (e.pipeline_id) e.pipeline_id, e.status::text AS status
              FROM report_executions_v e
              WHERE e.tenant_id = ${tenantId}::uuid AND e.workspace_id = ${workspaceId}::uuid
                AND NOT e.pipeline_deleted AND e.requested_at >= ${windowStart}::timestamptz
                AND e.status IN ('succeeded', 'failed', 'timed_out')
              ORDER BY e.pipeline_id, e.requested_at DESC
            ) x`;
          pipelines = { healthy: cnt(p[0]?.healthy), total: cnt(p[0]?.total) };
        }
        return {
          groups: groups.map((g) => ({
            status: g.status,
            severity: g.severity,
            scanType: g.scanType,
            n: cnt(g.n),
            pendingExceptions: cnt(g.pendingExceptions),
            expiring: cnt(g.expiring),
            newLast24Hours: cnt(g.newLast24Hours),
            slaBreached: cnt(g.slaBreached),
          })),
          pipelines,
        };
      });
    },

    async getPostureAsOf({ tenantId, workspaceId, day: asOfDay }) {
      uuid("tenantId", tenantId);
      uuid("workspaceId", workspaceId);
      day("day", asOfDay);
      return readTx(db, async (tx) => {
        // the day must have been rolled up: a succeeded incremental or close run of that day, or a backfill whose range covers it
        const runs = await tx.$queryRaw`
          SELECT 1 AS ok FROM report_rollup_runs
          WHERE tenant_id = ${tenantId}::uuid AND status = 'succeeded'
            AND day <= ${asOfDay}::date AND COALESCE(range_to, day) >= ${asOfDay}::date
          LIMIT 1`;
        if (runs.length === 0) return null;
        const rows = await tx.$queryRaw`
          SELECT d.scan_type::text AS "scanType", d.severity::text AS severity,
                 sum(d.open_count)::int AS open, sum(d.backlog_count)::int AS backlog, sum(d.wip_count)::int AS wip,
                 sum(d.awaiting_verification_count)::int AS "awaitingVerification",
                 sum(d.exceptions_in_force)::int AS "exceptionsInForce", sum(d.sla_breached)::int AS "slaBreached"
          FROM report_daily_findings d
          WHERE d.tenant_id = ${tenantId}::uuid AND d.workspace_id = ${workspaceId}::uuid AND d.day = ${asOfDay}::date
          GROUP BY 1, 2`;
        return {
          day: asOfDay,
          rows: rows.map((r) => ({
            scanType: r.scanType,
            severity: r.severity,
            open: cnt(r.open),
            backlog: cnt(r.backlog),
            wip: cnt(r.wip),
            awaitingVerification: cnt(r.awaitingVerification),
            exceptionsInForce: cnt(r.exceptionsInForce),
            slaBreached: cnt(r.slaBreached),
          })),
        };
      });
    },
  };
}
