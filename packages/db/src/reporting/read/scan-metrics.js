import { cnt, day, iso, num, readTx, uuid, OPEN_SQL } from "./tx.js";

/**
 * Scan activity (S-1 to S-3, S-6, S-7: rollup rows plus live percentiles), coverage (S-4, S-5) and SBOM (S-8). Coverage reads the
 * repositories, pipelines, executions and SBOM views (the first two added by amendment AM: connection state, enabled flags and the enabled
 * scan types of the current configuration version).
 * @param {any} db the read client
 */
export function buildScanMetricMethods(db) {
  return {
    async getScanActivity({ tenantId, workspaceId, from, to, start, endExclusive }) {
      uuid("tenantId", tenantId);
      uuid("workspaceId", workspaceId);
      day("from", from);
      day("to", to);
      const s = iso(start);
      const e = iso(endExclusive);
      return readTx(db, async (tx) => {
        const perDay = await tx.$queryRaw`
          SELECT d.day::text AS day, sum(d.total)::int AS total,
                 sum(d.succeeded_count)::int AS succeeded, sum(d.failed_count)::int AS failed, sum(d.partial_count)::int AS partial,
                 sum(d.timed_out_count)::int AS "timedOut", sum(d.cancelled_count)::int AS cancelled,
                 sum(d.skipped_count)::int AS skipped, sum(d.blocked_count)::int AS blocked,
                 sum(d.eligible_count)::int AS eligible,
                 sum(d.result_complete_count)::int AS "resultComplete", sum(d.result_partial_count)::int AS "resultPartial"
          FROM report_daily_executions d
          WHERE d.tenant_id = ${tenantId}::uuid AND d.workspace_id = ${workspaceId}::uuid
            AND d.day BETWEEN ${from}::date AND ${to}::date
          GROUP BY 1 ORDER BY 1`;
        // S-3 live over the window: duration of finished executions, queue wait of started ones
        const t = await tx.$queryRaw`
          SELECT
            percentile_cont(0.5) WITHIN GROUP (ORDER BY extract(epoch FROM (e.finished_at - e.started_at)) * 1000)
              FILTER (WHERE e.started_at IS NOT NULL AND e.finished_at IS NOT NULL)::float8 AS "durationMedian",
            percentile_cont(0.9) WITHIN GROUP (ORDER BY extract(epoch FROM (e.finished_at - e.started_at)) * 1000)
              FILTER (WHERE e.started_at IS NOT NULL AND e.finished_at IS NOT NULL)::float8 AS "durationP90",
            percentile_cont(0.5) WITHIN GROUP (ORDER BY extract(epoch FROM (e.started_at - e.requested_at)) * 1000)
              FILTER (WHERE e.started_at IS NOT NULL)::float8 AS "waitMedian",
            percentile_cont(0.9) WITHIN GROUP (ORDER BY extract(epoch FROM (e.started_at - e.requested_at)) * 1000)
              FILTER (WHERE e.started_at IS NOT NULL)::float8 AS "waitP90"
          FROM report_executions_v e
          WHERE e.tenant_id = ${tenantId}::uuid AND e.workspace_id = ${workspaceId}::uuid
            AND e.requested_at >= ${s}::timestamptz AND e.requested_at < ${e}::timestamptz`;
        const r = t[0] ?? {};
        return {
          perDay: perDay.map((d) => ({
            day: d.day,
            total: cnt(d.total),
            byStatus: {
              succeeded: cnt(d.succeeded),
              failed: cnt(d.failed),
              partial: cnt(d.partial),
              timed_out: cnt(d.timedOut),
              cancelled: cnt(d.cancelled),
              skipped: cnt(d.skipped),
              blocked: cnt(d.blocked),
            },
            eligible: cnt(d.eligible),
            resultComplete: cnt(d.resultComplete),
            resultPartial: cnt(d.resultPartial),
          })),
          duration: { medianMs: num(r.durationMedian), p90Ms: num(r.durationP90) },
          queueWait: { medianMs: num(r.waitMedian), p90Ms: num(r.waitP90) },
        };
      });
    },

    async getCoverage({ tenantId, workspaceId, now, windowDays }) {
      uuid("tenantId", tenantId);
      uuid("workspaceId", workspaceId);
      const windowStart = iso(new Date(now.getTime() - Number(windowDays) * 86_400_000));
      return readTx(db, async (tx) => {
        // S-4 (AM): the universe is the workspace's repositories that are enabled, not archived and not disconnected (`report_repositories_v`),
        // with their LIVE pipelines and how many of those are enabled (`report_pipelines_v`) and what the executions of the live pipelines show
        const repos = await tx.$queryRaw`
          SELECT r.repository_id::text AS "repositoryId", r.repository_name AS "repositoryName", r.connection_status AS "connectionStatus",
                 COALESCE(pl.live, 0)::int AS "livePipelines", COALESCE(pl.enabled, 0)::int AS "enabledPipelines",
                 COALESCE(ex.recent_success, false) AS "recentSuccess",
                 l.status AS "lastStatus", l.incomplete AS "lastIncomplete"
          FROM report_repositories_v r
          LEFT JOIN (
            SELECT p.repository_id, count(*)::int AS live, (count(*) FILTER (WHERE p.enabled))::int AS enabled
            FROM report_pipelines_v p
            WHERE p.tenant_id = ${tenantId}::uuid AND p.workspace_id = ${workspaceId}::uuid AND NOT p.pipeline_deleted
            GROUP BY p.repository_id
          ) pl ON pl.repository_id = r.repository_id
          LEFT JOIN (
            SELECT e.repository_id,
                   bool_or(e.status = 'succeeded' AND e.ref_type = 'branch' AND e.trust = 'trusted'
                           AND e.finished_at >= ${windowStart}::timestamptz) AS recent_success
            FROM report_executions_v e
            WHERE e.tenant_id = ${tenantId}::uuid AND e.workspace_id = ${workspaceId}::uuid AND NOT e.pipeline_deleted
            GROUP BY e.repository_id
          ) ex ON ex.repository_id = r.repository_id
          LEFT JOIN LATERAL (
            SELECT e2.status::text AS status, (e2.results_incomplete > 0) AS incomplete
            FROM report_executions_v e2
            WHERE e2.tenant_id = ${tenantId}::uuid AND e2.workspace_id = ${workspaceId}::uuid
              AND e2.repository_id = r.repository_id AND NOT e2.pipeline_deleted
              AND e2.status IN ('succeeded', 'failed', 'timed_out')
            ORDER BY e2.requested_at DESC LIMIT 1
          ) l ON true
          WHERE r.tenant_id = ${tenantId}::uuid AND r.workspace_id = ${workspaceId}::uuid
            AND r.enabled AND NOT r.archived AND r.connection_status <> 'disconnected'
          ORDER BY r.repository_name, r.repository_id
          LIMIT 5000`;
        // S-5 (AM): the enabled scan types come from the CURRENT configuration version of each live pipeline; the SBOM completeness is the
        // latest SBOM result of the pipeline (`lastComplete` of the other types is not known to the views)
        const pipes = await tx.$queryRaw`
          SELECT p.pipeline_id::text AS "pipelineId", p.pipeline_name AS "pipelineName", p.repository_id::text AS "repositoryId",
                 p.enabled AS "pipelineEnabled", p.scan_types_enabled AS "scanTypesEnabled", s.completeness AS "sbomCompleteness"
          FROM report_pipelines_v p
          LEFT JOIN (
            SELECT b.pipeline_id, max(b.result_completeness::text) AS completeness
            FROM report_sbom_latest_v b
            WHERE b.tenant_id = ${tenantId}::uuid AND b.workspace_id = ${workspaceId}::uuid
            GROUP BY b.pipeline_id
          ) s ON s.pipeline_id = p.pipeline_id
          WHERE p.tenant_id = ${tenantId}::uuid AND p.workspace_id = ${workspaceId}::uuid AND NOT p.pipeline_deleted
          ORDER BY p.pipeline_name, p.pipeline_id
          LIMIT 500`;
        return {
          repositories: repos.map((r) => ({
            repositoryId: r.repositoryId,
            repositoryName: r.repositoryName,
            connectionStatus: r.connectionStatus,
            livePipelines: cnt(r.livePipelines),
            enabledPipelines: cnt(r.enabledPipelines),
            recentSuccess: r.recentSuccess === true,
            lastStatus: r.lastStatus ?? null,
            lastIncomplete: r.lastIncomplete === true,
          })),
          pipelines: pipes.map((p) => ({
            pipelineId: p.pipelineId,
            pipelineName: p.pipelineName,
            repositoryId: p.repositoryId,
            pipelineEnabled: p.pipelineEnabled === true,
            scanTypesEnabled: p.scanTypesEnabled ?? [],
            sbomCompleteness: p.sbomCompleteness ?? null,
          })),
        };
      });
    },

    async getSbom({ tenantId, workspaceId, from, to }) {
      uuid("tenantId", tenantId);
      uuid("workspaceId", workspaceId);
      day("from", from);
      day("to", to);
      return readTx(db, async (tx) => {
        const totals = await tx.$queryRaw`
          SELECT count(*)::int AS components,
                 (count(*) FILTER (WHERE v.pipeline_id IS NOT NULL))::int AS vulnerable
          FROM report_sbom_latest_v c
          LEFT JOIN (
            SELECT DISTINCT f.pipeline_id, f.component_purl
            FROM report_findings_v f
            WHERE f.tenant_id = ${tenantId}::uuid AND f.workspace_id = ${workspaceId}::uuid
              AND f.scan_type = 'sca' AND f.status IN (${OPEN_SQL}) AND f.component_purl IS NOT NULL
          ) v ON v.pipeline_id = c.pipeline_id AND v.component_purl = c.component_purl
          WHERE c.tenant_id = ${tenantId}::uuid AND c.workspace_id = ${workspaceId}::uuid`;
        const eco = await tx.$queryRaw`
          SELECT c.ecosystem AS ecosystem, count(*)::int AS components
          FROM report_sbom_latest_v c
          WHERE c.tenant_id = ${tenantId}::uuid AND c.workspace_id = ${workspaceId}::uuid
          GROUP BY 1 ORDER BY 2 DESC, 1 LIMIT 100`;
        const trend = await tx.$queryRaw`
          SELECT d.day::text AS day, sum(d.components)::int AS components, sum(d.components_vulnerable)::int AS vulnerable
          FROM report_daily_sbom d
          WHERE d.tenant_id = ${tenantId}::uuid AND d.workspace_id = ${workspaceId}::uuid
            AND d.day BETWEEN ${from}::date AND ${to}::date
          GROUP BY 1 ORDER BY 1`;
        return {
          components: cnt(totals[0]?.components),
          vulnerable: cnt(totals[0]?.vulnerable),
          byEcosystem: eco.map((r) => ({
            ecosystem: r.ecosystem || "unknown",
            components: cnt(r.components),
          })),
          trend: trend.map((r) => ({
            day: r.day,
            components: cnt(r.components),
            vulnerable: cnt(r.vulnerable),
          })),
        };
      });
    },
  };
}
