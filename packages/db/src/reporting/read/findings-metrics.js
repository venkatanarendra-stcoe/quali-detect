import { FINDING_SEVERITIES, SLA_DEFAULT_HOURS } from "@qmentisai/shared";
import { cnt, day, iso, num, readTx, uuid, OPEN_SQL } from "./tx.js";

/**
 * Trends (rollup), remediation, SLA and aging (live over the findings view). Percentiles are `percentile_cont` over the bounded window
 * (they cannot be merged from rollups, SPEC 4 RPT-004). Every statement carries the tenant AND the workspace.
 * @param {any} db the read client
 */
export function buildFindingsMetricMethods(db) {
  const stats = (r) => ({
    count: cnt(r?.n),
    medianDays: num(r?.med),
    p90Days: num(r?.p90),
    meanDays: num(r?.mean),
  });

  return {
    async getTrends({ tenantId, workspaceId, from, to }) {
      uuid("tenantId", tenantId);
      uuid("workspaceId", workspaceId);
      day("from", from);
      day("to", to);
      return readTx(db, async (tx) => {
        const rows = await tx.$queryRaw`
          SELECT d.day::text AS day, d.severity::text AS severity,
                 sum(d.open_count)::int AS open, sum(d.backlog_count)::int AS backlog,
                 sum(d.awaiting_verification_count)::int AS "awaitingVerification",
                 sum(d.new_count)::int AS "new", sum(d.fixed_count)::int AS fixed,
                 sum(d.closed_other_count)::int AS "closedOther", sum(d.reopened_count)::int AS reopened
          FROM report_daily_findings d
          WHERE d.tenant_id = ${tenantId}::uuid AND d.workspace_id = ${workspaceId}::uuid
            AND d.day BETWEEN ${from}::date AND ${to}::date
          GROUP BY 1, 2`;
        const first = await tx.$queryRaw`
          SELECT (min(d.day))::text AS day FROM report_daily_findings d
          WHERE d.tenant_id = ${tenantId}::uuid AND d.workspace_id = ${workspaceId}::uuid`;
        // a day is covered when a succeeded run touched it (a day without a run is a GAP, not a zero)
        const runs = await tx.$queryRaw`
          SELECT mode::text AS mode, day::text AS day, range_to::text AS "rangeTo"
          FROM report_rollup_runs
          WHERE tenant_id = ${tenantId}::uuid AND status = 'succeeded'
            AND day <= ${to}::date AND COALESCE(range_to, day) >= ${from}::date
          LIMIT 5000`;
        return {
          rows: rows.map((r) => ({
            day: r.day,
            severity: r.severity,
            open: cnt(r.open),
            backlog: cnt(r.backlog),
            awaitingVerification: cnt(r.awaitingVerification),
            new: cnt(r.new),
            fixed: cnt(r.fixed),
            closedOther: cnt(r.closedOther),
            reopened: cnt(r.reopened),
          })),
          runs: runs.map((r) => ({ mode: r.mode, day: r.day, rangeTo: r.rangeTo ?? null })),
          dataFrom: first[0]?.day ?? null,
        };
      });
    },

    async getRemediation({ tenantId, workspaceId, from, to, start, endExclusive }) {
      uuid("tenantId", tenantId);
      uuid("workspaceId", workspaceId);
      day("from", from);
      day("to", to);
      const s = iso(start);
      const e = iso(endExclusive);
      // R-3 (the heaviest statement: the decisions view joins every review to its finding) runs in a SECOND read transaction in parallel
      const r3Query = readTx(
        db,
        (tx) => tx.$queryRaw`
          SELECT x.scan_type AS "scanType", count(*)::int AS n,
                 percentile_cont(0.5) WITHIN GROUP (ORDER BY x.d)::float8 AS med,
                 percentile_cont(0.9) WITHIN GROUP (ORDER BY x.d)::float8 AS p90,
                 avg(x.d)::float8 AS mean,
                 GROUPING(x.scan_type)::int AS overall
          FROM (
            SELECT f.scan_type::text AS scan_type,
                   greatest(extract(epoch FROM (r.first_at - f.first_detected_at)) / 86400.0, 0) AS d
            FROM (
              SELECT d.finding_id, min(d.created_at) AS first_at
              FROM report_decisions_v d
              WHERE d.tenant_id = ${tenantId}::uuid AND d.workspace_id = ${workspaceId}::uuid AND d.source = 'review'
                AND d.finding_id IN (
                  SELECT d2.finding_id FROM report_decisions_v d2
                  WHERE d2.tenant_id = ${tenantId}::uuid AND d2.workspace_id = ${workspaceId}::uuid AND d2.source = 'review'
                    AND d2.created_at >= ${s}::timestamptz AND d2.created_at < ${e}::timestamptz)
              GROUP BY d.finding_id
            ) r
            JOIN report_findings_v f ON f.tenant_id = ${tenantId}::uuid AND f.workspace_id = ${workspaceId}::uuid AND f.id = r.finding_id
            WHERE r.first_at >= ${s}::timestamptz AND r.first_at < ${e}::timestamptz
          ) x
          GROUP BY GROUPING SETS ((), (x.scan_type))`,
      );
      const mainQuery = readTx(db, async (tx) => {
        // R-1: findings verified in the period, from first detection; median first, p90, mean secondary (rule: never a bare mean)
        const r1 = await tx.$queryRaw`
          SELECT x.severity, count(*)::int AS n,
                 percentile_cont(0.5) WITHIN GROUP (ORDER BY x.d)::float8 AS med,
                 percentile_cont(0.9) WITHIN GROUP (ORDER BY x.d)::float8 AS p90,
                 avg(x.d)::float8 AS mean,
                 (count(*) FILTER (WHERE x.reopen_count > 0))::int AS "reopenedThenFixed",
                 GROUPING(x.severity)::int AS overall
          FROM (
            SELECT f.severity::text AS severity, f.reopen_count,
                   greatest(extract(epoch FROM (f.verified_at - f.first_detected_at)) / 86400.0, 0) AS d
            FROM report_findings_v f
            WHERE f.tenant_id = ${tenantId}::uuid AND f.workspace_id = ${workspaceId}::uuid
              AND f.verified_at >= ${s}::timestamptz AND f.verified_at < ${e}::timestamptz
          ) x
          GROUP BY GROUPING SETS ((), (x.severity))`;
        // R-7: verification lag = verified - fix claimed
        const r7 = await tx.$queryRaw`
          SELECT count(*)::int AS n,
                 percentile_cont(0.5) WITHIN GROUP (ORDER BY x.d)::float8 AS med,
                 percentile_cont(0.9) WITHIN GROUP (ORDER BY x.d)::float8 AS p90,
                 avg(x.d)::float8 AS mean
          FROM (
            SELECT greatest(extract(epoch FROM (f.verified_at - f.fix_claimed_at)) / 86400.0, 0) AS d
            FROM report_findings_v f
            WHERE f.tenant_id = ${tenantId}::uuid AND f.workspace_id = ${workspaceId}::uuid
              AND f.verified_at >= ${s}::timestamptz AND f.verified_at < ${e}::timestamptz AND f.fix_claimed_at IS NOT NULL
          ) x`;
        // velocity (R-2) and the reopen rate (R-8) come from the daily rollup
        const velocity = await tx.$queryRaw`
          SELECT (date_trunc('week', d.day::timestamp))::date::text AS "weekStart", sum(d.fixed_count)::int AS fixed
          FROM report_daily_findings d
          WHERE d.tenant_id = ${tenantId}::uuid AND d.workspace_id = ${workspaceId}::uuid
            AND d.day BETWEEN ${from}::date AND ${to}::date
          GROUP BY 1 ORDER BY 1`;
        const flow = await tx.$queryRaw`
          SELECT COALESCE(sum(d.reopened_count), 0)::int AS reopened, COALESCE(sum(d.fixed_count), 0)::int AS fixed
          FROM report_daily_findings d
          WHERE d.tenant_id = ${tenantId}::uuid AND d.workspace_id = ${workspaceId}::uuid
            AND d.day BETWEEN ${from}::date AND ${to}::date`;
        const overall = r1.find((r) => cnt(r.overall) === 1);
        return {
          timeToRemediate: {
            overall: stats(overall),
            bySeverity: Object.fromEntries(
              FINDING_SEVERITIES.map((sev) => [
                sev,
                stats(r1.find((r) => cnt(r.overall) === 0 && r.severity === sev)),
              ]),
            ),
            reopenedThenFixed: cnt(overall?.reopenedThenFixed),
          },
          verificationLag: stats(r7[0]),
          velocity: velocity.map((v) => ({ weekStart: v.weekStart, fixed: cnt(v.fixed) })),
          reopen: { reopened: cnt(flow[0]?.reopened), fixed: cnt(flow[0]?.fixed) },
        };
      });
      const [main, r3] = await Promise.all([mainQuery, r3Query]);
      return {
        ...main,
        timeToFirstDecision: {
          overall: stats(r3.find((r) => cnt(r.overall) === 1)),
          byType: Object.fromEntries(
            ["sca", "sast", "secrets"].map((t) => [
              t,
              stats(r3.find((r) => cnt(r.overall) === 0 && r.scanType === t)),
            ]),
          ),
        },
      };
    },

    async getSla({ tenantId, workspaceId, start, endExclusive, now }) {
      uuid("tenantId", tenantId);
      uuid("workspaceId", workspaceId);
      const s = iso(start);
      const e = iso(endExclusive);
      const nowIso = iso(now);
      const h = SLA_DEFAULT_HOURS;
      return readTx(db, async (tx) => {
        // R-5: open findings with a running clock (info has none), the three derived states against ONE `now` (SL-3)
        const open = await tx.$queryRaw`
          SELECT f.severity::text AS severity,
                 (count(*) FILTER (WHERE f.sla_due_at < ${nowIso}::timestamptz))::int AS breached,
                 (count(*) FILTER (WHERE f.sla_due_at >= ${nowIso}::timestamptz AND f.sla_started_at IS NOT NULL
                     AND f.sla_due_at > f.sla_started_at
                     AND (f.sla_due_at - ${nowIso}::timestamptz) <= (f.sla_due_at - f.sla_started_at) * 0.25::float8))::int AS "dueSoon",
                 (count(*) FILTER (WHERE f.sla_due_at >= ${nowIso}::timestamptz AND NOT (f.sla_started_at IS NOT NULL
                     AND f.sla_due_at > f.sla_started_at
                     AND (f.sla_due_at - ${nowIso}::timestamptz) <= (f.sla_due_at - f.sla_started_at) * 0.25::float8)))::int AS "onTrack"
          FROM report_findings_v f
          WHERE f.tenant_id = ${tenantId}::uuid AND f.workspace_id = ${workspaceId}::uuid
            AND f.status IN (${OPEN_SQL}) AND f.sla_due_at IS NOT NULL AND f.severity <> 'info'
          GROUP BY f.severity`;
        // R-4: closed in the period; the stopped clock keeps `sla_started_at`, so the target (the shared default hours: the views do not
        // expose the tenant's overrides) is added to it
        const closed = await tx.$queryRaw`
          SELECT f.severity::text AS severity, count(*)::int AS "withTarget",
                 (count(*) FILTER (WHERE f.verified_at <= f.sla_started_at + (CASE f.severity::text
                     WHEN 'critical' THEN ${h.critical}::int WHEN 'high' THEN ${h.high}::int
                     WHEN 'medium' THEN ${h.medium}::int ELSE ${h.low}::int END) * interval '1 hour'))::int AS "withinSla"
          FROM report_findings_v f
          WHERE f.tenant_id = ${tenantId}::uuid AND f.workspace_id = ${workspaceId}::uuid
            AND f.verified_at >= ${s}::timestamptz AND f.verified_at < ${e}::timestamptz
            AND f.sla_started_at IS NOT NULL AND f.severity <> 'info'
          GROUP BY 1`;
        return {
          open: open.map((r) => ({
            severity: r.severity,
            onTrack: cnt(r.onTrack),
            dueSoon: cnt(r.dueSoon),
            breached: cnt(r.breached),
          })),
          closed: closed.map((r) => ({
            severity: r.severity,
            withTarget: cnt(r.withTarget),
            withinSla: cnt(r.withinSla),
          })),
        };
      });
    },

    async getAging({ tenantId, workspaceId, now }) {
      uuid("tenantId", tenantId);
      uuid("workspaceId", workspaceId);
      const nowIso = iso(now);
      return readTx(db, async (tx) => {
        const buckets = await tx.$queryRaw`
          SELECT x.severity, x.bucket, count(*)::int AS n
          FROM (
            SELECT f.severity::text AS severity,
                   CASE WHEN a <= 7 THEN '0-7' WHEN a <= 30 THEN '8-30' WHEN a <= 90 THEN '31-90' ELSE '90+' END AS bucket
            FROM (
              SELECT f.severity, floor(extract(epoch FROM (${nowIso}::timestamptz - f.first_detected_at)) / 86400.0) AS a
              FROM report_findings_v f
              WHERE f.tenant_id = ${tenantId}::uuid AND f.workspace_id = ${workspaceId}::uuid AND f.status IN (${OPEN_SQL})
            ) f
          ) x
          GROUP BY 1, 2`;
        const oldest = await tx.$queryRaw`
          SELECT f.id::text AS id, f.title, f.severity::text AS severity, f.first_detected_at AS "firstDetectedAt",
                 f.repository_name AS "repositoryName"
          FROM report_findings_v f
          WHERE f.tenant_id = ${tenantId}::uuid AND f.workspace_id = ${workspaceId}::uuid
            AND f.status IN (${OPEN_SQL}) AND f.severity IN ('critical', 'high')
          ORDER BY f.first_detected_at ASC, f.id ASC
          LIMIT 10`;
        return {
          buckets: buckets.map((r) => ({ severity: r.severity, bucket: r.bucket, n: cnt(r.n) })),
          oldest: oldest.map((r) => ({
            id: r.id,
            title: r.title,
            severity: r.severity,
            firstDetectedAt: new Date(r.firstDetectedAt),
            repositoryName: r.repositoryName ?? null,
          })),
        };
      });
    },
  };
}
