import { FINDING_SEVERITIES, computeRiskScore, compareTopRisk } from "@qmentisai/shared";
import { Prisma, cnt, day, iso, readTx, uuid, OPEN_SQL } from "./tx.js";

/**
 * Breakdowns (B-2, B-3, B-5 with keyset pages), top risk (B-4), workload (B-6) and the overview (B-1), all LIVE over the findings view and
 * always scoped by tenant AND workspace(s). The grouping expressions below are allow-listed constants chosen by the validated `by`, never
 * input text. Soft-deleted pipelines are grouped as "(deleted)" so the totals still add up (SPEC 6.6 B-3).
 * @param {any} db the read client
 */
export function buildBreakdownMethods(db) {
  const severityCounts = (r) => Object.fromEntries(FINDING_SEVERITIES.map((s) => [s, cnt(r?.[s])]));
  const SEVERITY_COLUMNS = Prisma.sql`
    (count(*) FILTER (WHERE f.severity = 'critical'))::int AS critical, (count(*) FILTER (WHERE f.severity = 'high'))::int AS high,
    (count(*) FILTER (WHERE f.severity = 'medium'))::int AS medium, (count(*) FILTER (WHERE f.severity = 'low'))::int AS low,
    (count(*) FILTER (WHERE f.severity = 'info'))::int AS info`;
  const DIMENSIONS = Object.freeze({
    repository: {
      key: Prisma.sql`f.repository_id::text`,
      label: Prisma.sql`max(f.repository_name)`,
      deleted: Prisma.sql`false`,
    },
    pipeline: {
      key: Prisma.sql`CASE WHEN f.pipeline_deleted THEN 'deleted' ELSE f.pipeline_id::text END`,
      label: Prisma.sql`CASE WHEN bool_or(f.pipeline_deleted) THEN '(deleted)' ELSE max(f.pipeline_name) END`,
      deleted: Prisma.sql`bool_or(f.pipeline_deleted)`,
    },
    scan_type: {
      key: Prisma.sql`f.scan_type::text`,
      label: Prisma.sql`f.scan_type::text`,
      deleted: Prisma.sql`false`,
    },
    rule: { key: Prisma.sql`f.rule_id`, label: Prisma.sql`f.rule_id`, deleted: Prisma.sql`false` },
  });

  return {
    async getBreakdown({ tenantId, workspaceId, by, limit, after }) {
      uuid("tenantId", tenantId);
      uuid("workspaceId", workspaceId);
      const dim = Object.hasOwn(DIMENSIONS, by) ? DIMENSIONS[by] : null;
      if (!dim) throw new TypeError("unknown breakdown dimension");
      const take = Math.min(Math.max(Number(limit) || 25, 1), 100);
      const hasAfter = Boolean(after);
      const afterOpen = hasAfter ? Number(after.open) : 0;
      const afterKey = hasAfter ? String(after.key) : "";
      return readTx(db, async (tx) => {
        const rows = await tx.$queryRaw`
          WITH g AS (
            SELECT ${dim.key} AS key, ${dim.label} AS label, ${dim.deleted} AS deleted, count(*)::int AS open,
                   ${SEVERITY_COLUMNS},
                   (count(*) FILTER (WHERE f.sla_due_at IS NOT NULL AND f.sla_due_at < now()))::int AS breached
            FROM report_findings_v f
            WHERE f.tenant_id = ${tenantId}::uuid AND f.workspace_id = ${workspaceId}::uuid AND f.status IN (${OPEN_SQL})
            GROUP BY 1${by === "scan_type" || by === "rule" ? Prisma.sql`, 2` : Prisma.empty}
          ), t AS (SELECT g.*, (sum(g.open) OVER ())::int AS total FROM g)
          SELECT * FROM t
          WHERE ${hasAfter}::boolean = false OR t.open < ${afterOpen}::int OR (t.open = ${afterOpen}::int AND t.key > ${afterKey}::text)
          ORDER BY t.open DESC, t.key ASC
          LIMIT ${take + 1}::int`;
        const page = rows.slice(0, take);
        let lastScan = new Map();
        if (page.length > 0 && (by === "repository" || by === "pipeline")) {
          const ids = page.map((r) => r.key).filter((k) => k !== "deleted");
          const col = by === "repository" ? Prisma.sql`e.repository_id` : Prisma.sql`e.pipeline_id`;
          const scans = await tx.$queryRaw`
            SELECT DISTINCT ON (${col}) ${col}::text AS key, e.status::text AS status, e.requested_at AS at
            FROM report_executions_v e
            WHERE e.tenant_id = ${tenantId}::uuid AND e.workspace_id = ${workspaceId}::uuid
              AND ${col} = ANY(${ids}::uuid[])
            ORDER BY ${col}, e.requested_at DESC`;
          lastScan = new Map(scans.map((r) => [r.key, { status: r.status, at: iso(r.at) }]));
        }
        const items = page.map((r) => ({
          key: r.key,
          label: r.label ?? r.key,
          deleted: r.deleted === true,
          open: cnt(r.open),
          bySeverity: severityCounts(r),
          slaBreached: cnt(r.breached),
          share: cnt(r.total) > 0 ? cnt(r.open) / cnt(r.total) : 0,
          lastScan:
            by === "repository" || by === "pipeline" ? (lastScan.get(r.key) ?? null) : undefined,
        }));
        const last = items.at(-1);
        return {
          items,
          next: rows.length > take && last ? { open: last.open, key: last.key } : null,
        };
      });
    },

    async getTopRisk({ tenantId, workspaceId, limit }) {
      uuid("tenantId", tenantId);
      uuid("workspaceId", workspaceId);
      const take = Math.min(Math.max(Number(limit) || 10, 1), 50);
      const rows = await readTx(
        db,
        (tx) => tx.$queryRaw`
          SELECT f.repository_id::text AS "repositoryId", max(f.repository_name) AS "repositoryName",
                 ${SEVERITY_COLUMNS},
                 (count(*) FILTER (WHERE f.severity IN ('critical', 'high') AND f.sla_due_at IS NOT NULL AND f.sla_due_at < now()))::int AS "breachedCriticalHigh",
                 min(f.first_detected_at) FILTER (WHERE f.severity = 'critical') AS "oldestOpenCriticalAt"
          FROM report_findings_v f
          WHERE f.tenant_id = ${tenantId}::uuid AND f.workspace_id = ${workspaceId}::uuid AND f.status IN (${OPEN_SQL})
          GROUP BY 1
          LIMIT 20000`,
      );
      return rankRepositories(rows).slice(0, take);
    },

    async getWorkload({ tenantId, workspaceId, now }) {
      uuid("tenantId", tenantId);
      uuid("workspaceId", workspaceId);
      const nowIso = iso(now);
      return readTx(db, async (tx) => {
        const rows = await tx.$queryRaw`
          SELECT f.assignee_user_id::text AS "userId", max(f.assignee_display_name) AS "displayName", count(*)::int AS open,
                 (count(*) FILTER (WHERE f.sla_due_at IS NOT NULL AND f.sla_due_at >= ${nowIso}::timestamptz AND f.sla_started_at IS NOT NULL
                     AND f.sla_due_at > f.sla_started_at
                     AND (f.sla_due_at - ${nowIso}::timestamptz) <= (f.sla_due_at - f.sla_started_at) * 0.25::float8))::int AS "dueSoon",
                 (count(*) FILTER (WHERE f.sla_due_at IS NOT NULL AND f.sla_due_at < ${nowIso}::timestamptz))::int AS breached
          FROM report_findings_v f
          WHERE f.tenant_id = ${tenantId}::uuid AND f.workspace_id = ${workspaceId}::uuid AND f.status IN (${OPEN_SQL})
            AND f.assignee_user_id IS NOT NULL
          GROUP BY f.assignee_user_id
          ORDER BY 3 DESC, 1
          LIMIT 500`;
        const unassigned = await tx.$queryRaw`
          SELECT count(*)::int AS n FROM report_findings_v f
          WHERE f.tenant_id = ${tenantId}::uuid AND f.workspace_id = ${workspaceId}::uuid AND f.status IN (${OPEN_SQL})
            AND f.assignee_user_id IS NULL`;
        const assignees = rows.map((r) => ({
          userId: r.userId,
          displayName: r.displayName,
          open: cnt(r.open),
          dueSoon: cnt(r.dueSoon),
          breached: cnt(r.breached),
        }));
        return { assignees, unassigned: cnt(unassigned[0]?.n) };
      });
    },

    async getOverview({ tenantId, workspaceIds, from, to, limit }) {
      uuid("tenantId", tenantId);
      day("from", from);
      day("to", to);
      const ids = (workspaceIds ?? []).map((id) => uuid("workspaceId", id));
      if (ids.length === 0) return { findings: [], executions: [], topRisk: [] };
      const take = Math.min(Math.max(Number(limit) || 10, 1), 50);
      return readTx(db, async (tx) => {
        const findings = await tx.$queryRaw`
          SELECT f.workspace_id::text AS "workspaceId", f.severity::text AS severity, count(*)::int AS open,
                 (count(*) FILTER (WHERE f.sla_due_at IS NOT NULL AND f.sla_due_at < now()))::int AS breached
          FROM report_findings_v f
          WHERE f.tenant_id = ${tenantId}::uuid AND f.workspace_id = ANY(${ids}::uuid[]) AND f.status IN (${OPEN_SQL})
          GROUP BY 1, 2`;
        const executions = await tx.$queryRaw`
          SELECT d.workspace_id::text AS "workspaceId", sum(d.total)::int AS total,
                 sum(d.succeeded_count)::int AS succeeded, sum(d.failed_count)::int AS failed,
                 sum(d.partial_count)::int AS partial, sum(d.timed_out_count)::int AS "timedOut"
          FROM report_daily_executions d
          WHERE d.tenant_id = ${tenantId}::uuid AND d.workspace_id = ANY(${ids}::uuid[])
            AND d.day BETWEEN ${from}::date AND ${to}::date
          GROUP BY 1`;
        const repos = await tx.$queryRaw`
          SELECT f.workspace_id::text AS "workspaceId", f.repository_id::text AS "repositoryId", max(f.repository_name) AS "repositoryName",
                 ${SEVERITY_COLUMNS},
                 (count(*) FILTER (WHERE f.severity IN ('critical', 'high') AND f.sla_due_at IS NOT NULL AND f.sla_due_at < now()))::int AS "breachedCriticalHigh",
                 min(f.first_detected_at) FILTER (WHERE f.severity = 'critical') AS "oldestOpenCriticalAt"
          FROM report_findings_v f
          WHERE f.tenant_id = ${tenantId}::uuid AND f.workspace_id = ANY(${ids}::uuid[]) AND f.status IN (${OPEN_SQL})
          GROUP BY 1, 2
          LIMIT 50000`;
        // the best `take` repositories of EACH workspace; the service keeps only the workspaces whose finding key the caller holds
        const byWorkspace = new Map();
        for (const r of repos) {
          if (!byWorkspace.has(r.workspaceId)) byWorkspace.set(r.workspaceId, []);
          byWorkspace.get(r.workspaceId).push(r);
        }
        const topRisk = [...byWorkspace.entries()].flatMap(([workspaceId, list]) =>
          rankRepositories(list)
            .slice(0, take)
            .map((r) => ({ ...r, workspaceId })),
        );
        return {
          findings: findings.map((r) => ({
            workspaceId: r.workspaceId,
            severity: r.severity,
            open: cnt(r.open),
            breached: cnt(r.breached),
          })),
          executions: executions.map((r) => ({
            workspaceId: r.workspaceId,
            total: cnt(r.total),
            succeeded: cnt(r.succeeded),
            failed: cnt(r.failed),
            partial: cnt(r.partial),
            timedOut: cnt(r.timedOut),
          })),
          topRisk,
        };
      });
    },
  };
}

/**
 * Scores (the shared formula) and orders repository rows (the shared comparator).
 * @param {Array<Record<string, any>>} rows
 */
function rankRepositories(rows) {
  return rows
    .map((r) => {
      const counts = {
        critical: cnt(r.critical),
        high: cnt(r.high),
        medium: cnt(r.medium),
        low: cnt(r.low),
        breachedCriticalHigh: cnt(r.breachedCriticalHigh),
      };
      return {
        repositoryId: r.repositoryId,
        repositoryName: r.repositoryName,
        ...counts,
        score: computeRiskScore(counts),
        oldestOpenCriticalAt: r.oldestOpenCriticalAt ? new Date(r.oldestOpenCriticalAt) : null,
      };
    })
    .sort((a, b) =>
      compareTopRisk({ ...a, name: a.repositoryName }, { ...b, name: b.repositoryName }),
    );
}
