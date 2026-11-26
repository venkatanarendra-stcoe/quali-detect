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
                 (min(day) FILTER (WHERE status = 'succeeded' AND mode IN ('incremental', 'close')))::text AS "firstExactDay",
                 COALESCE(bool_or(status = 'running' AND mode = 'backfill' AND started_at > now() - interval '6 hours'), false) AS recomputing
          FROM report_rollup_runs WHERE tenant_id = ${tenantId}::uuid`,
      );
      const r = rows[0] ?? {};
      return {
        lastSuccessAt: r.lastSuccessAt ? new Date(r.lastSuccessAt) : null,
        firstDay: r.firstDay ?? null,
        // the first day of the EXACT state series (AM 17.5): the earliest succeeded live run (incremental or close); a backfill never counts
        firstExactDay: r.firstExactDay ?? null,
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
        let connections = null;
        if (includePipelines) {
          // P-10 (AM): enabled, not deleted pipelines (`report_pipelines_v`) whose latest FINISHED execution of the last 90 days succeeded
          const p = await tx.$queryRaw`
            SELECT count(*)::int AS total, (count(*) FILTER (WHERE x.status = 'succeeded'))::int AS healthy
            FROM report_pipelines_v p
            LEFT JOIN LATERAL (
              SELECT e.status::text AS status
              FROM report_executions_v e
              WHERE e.tenant_id = p.tenant_id AND e.workspace_id = p.workspace_id AND e.pipeline_id = p.pipeline_id
                AND e.requested_at >= ${windowStart}::timestamptz AND e.status IN ('succeeded', 'failed', 'timed_out')
              ORDER BY e.requested_at DESC LIMIT 1
            ) x ON true
            WHERE p.tenant_id = ${tenantId}::uuid AND p.workspace_id = ${workspaceId}::uuid AND p.enabled AND NOT p.pipeline_deleted`;
          pipelines = { healthy: cnt(p[0]?.healthy), total: cnt(p[0]?.total) };
          // the GitHub connection tile (C-4, O-5): the workspace's repositories by connection state
          const c = await tx.$queryRaw`
            SELECT r.connection_status AS status, count(*)::int AS n
            FROM report_repositories_v r
            WHERE r.tenant_id = ${tenantId}::uuid AND r.workspace_id = ${workspaceId}::uuid
            GROUP BY 1`;
          connections = { active: 0, unavailable: 0, disconnected: 0 };
          for (const row of c) if (row.status in connections) connections[row.status] = cnt(row.n);
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
          connections,
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
        // the state counters of a day are EXACT only when a live run (incremental or close) wrote that day: a backfill writes flow, never state,
        // and a day before the first live run has no state at all (forward-only series, ADR-015 item 3, AM 17.5)
        const exact = await tx.$queryRaw`
          SELECT 1 AS ok FROM report_rollup_runs
          WHERE tenant_id = ${tenantId}::uuid AND status = 'succeeded' AND mode IN ('incremental', 'close') AND day = ${asOfDay}::date
          LIMIT 1`;
        if (exact.length === 0) return { day: asOfDay, exact: false, rows: [] };
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
          exact: true,
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
