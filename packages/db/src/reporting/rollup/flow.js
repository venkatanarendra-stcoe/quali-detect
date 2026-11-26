import {
  FLOW_CLOSED_OTHER_TO_STATUSES,
  FLOW_FIXED_TO_STATUSES,
  FLOW_REOPENED_TO_STATUSES,
  OPEN_FINDING_STATUSES,
} from "@qmentisai/shared";
import { assertUuid, dayThresholds, inTransaction, num } from "./util.js";

/**
 * The per-day series of the rollup (docs/modules/reporting-dashboards/SPEC.md 6.2 T-1, 6.4 S-1 S-2 S-6 S-7 S-8, 6.5 Q-1 to Q-5, 8.2). Each
 * function buckets by the TENANT-LOCAL day. The day boundaries come from the shared period helpers (`dayThresholds`), passed as epoch
 * seconds and applied with `width_bucket`, so a DST day (23 or 25 hours) is exact and the database never decides what a local day is.
 * Every value is a bind parameter; nothing is interpolated.
 */

const day = (days, k) => days[k - 1];

/**
 * Flow counters per day (T-1): `new` = a history row with no `from_status`; `fixed` = into `verified_fixed`; `closed_other` = into
 * `false_positive`, `suppressed` or `accepted_risk`; `reopened` = into `reopened`. A finding's flow is attributed to its CURRENT severity
 * (the history row carries none): the totals per day are exact, the split by severity is not (see `state.js`). Only the flow fields are set.
 * @param {any} db @returns {(args: { tenantId: string, from: string, to: string, timeZone: string }) => Promise<any[]>}
 */
export function buildComputeFindingsFlow(db) {
  return async function computeFindingsFlow({ tenantId, from, to, timeZone }) {
    assertUuid(tenantId, "tenantId");
    const { days, thresholds, start, endExclusive } = dayThresholds(from, to, timeZone);
    const fixed = [...FLOW_FIXED_TO_STATUSES];
    const closed = [...FLOW_CLOSED_OTHER_TO_STATUSES];
    const reopened = [...FLOW_REOPENED_TO_STATUSES];
    const { rows, newest } = await inTransaction(db, async (tx) => ({
      newest: await tx.$queryRaw`
        SELECT e.id::text AS id FROM report_status_events_v e
        WHERE e.tenant_id = ${tenantId}::uuid AND e.created_at < ${endExclusive}::timestamptz
        ORDER BY e.created_at DESC, e.rev DESC, e.id DESC LIMIT 1`,
      rows: await tx.$queryRaw`
        WITH ev AS (
          SELECT e.workspace_id, e.repository_id, e.pipeline_id, e.scan_type::text AS scan_type, e.finding_id,
            width_bucket(EXTRACT(EPOCH FROM e.created_at)::float8, ${thresholds}::float8[]) AS k,
            (e.from_status IS NULL) AS is_new,
            (e.to_status::text = ANY(${fixed}::text[])) AS is_fixed,
            (e.to_status::text = ANY(${closed}::text[])) AS is_closed,
            (e.to_status::text = ANY(${reopened}::text[])) AS is_reopened
          FROM report_status_events_v e
          WHERE e.tenant_id = ${tenantId}::uuid AND e.created_at >= ${start}::timestamptz AND e.created_at < ${endExclusive}::timestamptz
        )
        SELECT ev.k::int AS k, ev.workspace_id::text AS "workspaceId", ev.repository_id::text AS "repositoryId", ev.pipeline_id::text AS "pipelineId",
          ev.scan_type AS "scanType", f.severity::text AS severity,
          count(*) FILTER (WHERE ev.is_new) AS "newCount",
          count(*) FILTER (WHERE ev.is_fixed) AS "fixedCount",
          count(*) FILTER (WHERE ev.is_closed) AS "closedOtherCount",
          count(*) FILTER (WHERE ev.is_reopened) AS "reopenedCount"
        FROM ev
        JOIN report_findings_v f ON f.tenant_id = ${tenantId}::uuid AND f.id = ev.finding_id
        WHERE ev.k BETWEEN 1 AND ${days.length}::int AND (ev.is_new OR ev.is_fixed OR ev.is_closed OR ev.is_reopened)
        GROUP BY ev.k, ev.workspace_id, ev.repository_id, ev.pipeline_id, ev.scan_type, f.severity
        ORDER BY ev.k, ev.pipeline_id, ev.scan_type, f.severity`,
    }));
    const out = rows.map((r) => ({
      tenantId,
      workspaceId: r.workspaceId,
      repositoryId: r.repositoryId,
      pipelineId: r.pipelineId,
      day: day(days, r.k),
      scanType: r.scanType,
      severity: r.severity,
      newCount: num(r.newCount),
      fixedCount: num(r.fixedCount),
      closedOtherCount: num(r.closedOtherCount),
      reopenedCount: num(r.reopenedCount),
    }));
    // "data as of": the newest history row before the end of the range (a property of the array, not a row field)
    Object.defineProperty(out, "asOfHistoryId", {
      value: newest[0]?.id ?? null,
      enumerable: false,
    });
    return out;
  };
}

/**
 * Executions per day (S-1, S-2, S-6, S-7) by `requested_at`. `eligible` = a succeeded, full, trusted execution of a branch whose results
 * are all complete (the rule 7 approximation of "trusted, default branch and complete": the view carries no branch name).
 * @param {any} db @returns {(args: { tenantId: string, from: string, to: string, timeZone: string }) => Promise<any[]>}
 */
export function buildComputeExecutionsDays(db) {
  return async function computeExecutionsDays({ tenantId, from, to, timeZone }) {
    assertUuid(tenantId, "tenantId");
    const { days, thresholds, start, endExclusive } = dayThresholds(from, to, timeZone);
    const rows = await inTransaction(
      db,
      (tx) => tx.$queryRaw`
        SELECT width_bucket(EXTRACT(EPOCH FROM x.requested_at)::float8, ${thresholds}::float8[])::int AS k,
          x.workspace_id::text AS "workspaceId", x.repository_id::text AS "repositoryId", x.pipeline_id::text AS "pipelineId",
          count(*) AS total,
          count(*) FILTER (WHERE x.status::text = 'succeeded') AS "succeededCount",
          count(*) FILTER (WHERE x.status::text = 'failed') AS "failedCount",
          count(*) FILTER (WHERE x.status::text = 'partial') AS "partialCount",
          count(*) FILTER (WHERE x.status::text = 'timed_out') AS "timedOutCount",
          count(*) FILTER (WHERE x.status::text = 'cancelled') AS "cancelledCount",
          count(*) FILTER (WHERE x.status::text = 'skipped') AS "skippedCount",
          count(*) FILTER (WHERE x.status::text = 'blocked') AS "blockedCount",
          COALESCE(sum(FLOOR(EXTRACT(EPOCH FROM (x.finished_at - x.started_at)) * 1000))
            FILTER (WHERE x.started_at IS NOT NULL AND x.finished_at IS NOT NULL AND x.finished_at >= x.started_at), 0)::bigint AS "durationMsSum",
          COALESCE(sum(FLOOR(EXTRACT(EPOCH FROM (x.started_at - x.requested_at)) * 1000))
            FILTER (WHERE x.started_at IS NOT NULL AND x.started_at >= x.requested_at), 0)::bigint AS "queueWaitMsSum",
          count(*) FILTER (WHERE x.status::text = 'succeeded' AND x.scan_kind::text = 'full' AND x.trust::text = 'trusted'
            AND x.ref_type::text = 'branch' AND x.results_complete > 0 AND x.results_incomplete = 0) AS "eligibleCount",
          COALESCE(sum(x.results_complete), 0)::bigint AS "resultCompleteCount",
          COALESCE(sum(x.results_incomplete), 0)::bigint AS "resultPartialCount"
        FROM report_executions_v x
        WHERE x.tenant_id = ${tenantId}::uuid AND x.requested_at >= ${start}::timestamptz AND x.requested_at < ${endExclusive}::timestamptz
        GROUP BY 1, 2, 3, 4
        ORDER BY 1, 4`,
    );
    return rows.map((r) => ({
      tenantId,
      workspaceId: r.workspaceId,
      repositoryId: r.repositoryId,
      pipelineId: r.pipelineId,
      day: day(days, r.k),
      total: num(r.total),
      succeededCount: num(r.succeededCount),
      failedCount: num(r.failedCount),
      partialCount: num(r.partialCount),
      timedOutCount: num(r.timedOutCount),
      cancelledCount: num(r.cancelledCount),
      skippedCount: num(r.skippedCount),
      blockedCount: num(r.blockedCount),
      durationMsSum: num(r.durationMsSum),
      queueWaitMsSum: num(r.queueWaitMsSum),
      eligibleCount: num(r.eligibleCount),
      resultCompleteCount: num(r.resultCompleteCount),
      resultPartialCount: num(r.resultPartialCount),
    }));
  };
}

/**
 * Decisions per day at DECISION time (Q-1 to Q-5): approved review decisions by `decided_at`, with the advisory that existed at the
 * decision (`advisory_id_at_decision`, a `ok` row). Agreement matrix: suggestion against the human decision; `uncertain` apart;
 * `override_confident` = the human went against a suggestion of confidence 80 or more.
 * @param {any} db @returns {(args: { tenantId: string, from: string, to: string, timeZone: string }) => Promise<any[]>}
 */
export function buildComputeDecisionsDays(db) {
  return async function computeDecisionsDays({ tenantId, from, to, timeZone }) {
    assertUuid(tenantId, "tenantId");
    const { days, thresholds, start, endExclusive } = dayThresholds(from, to, timeZone);
    const rows = await inTransaction(
      db,
      (tx) => tx.$queryRaw`
        WITH dec AS (
          SELECT d.workspace_id, d.repository_id, d.pipeline_id, d.scan_type::text AS scan_type, d.decision,
            width_bucket(EXTRACT(EPOCH FROM d.decided_at)::float8, ${thresholds}::float8[]) AS k,
            a.suggestion, a.confidence
          FROM report_decisions_v d
          LEFT JOIN report_advisories_v a ON a.tenant_id = d.tenant_id AND a.id = d.advisory_id_at_decision AND a.status = 'ok'
          WHERE d.tenant_id = ${tenantId}::uuid AND d.source = 'review' AND d.state = 'approved'
            AND d.decision IN ('true_positive', 'false_positive')
            AND d.decided_at >= ${start}::timestamptz AND d.decided_at < ${endExclusive}::timestamptz
        )
        SELECT k::int AS k, workspace_id::text AS "workspaceId", repository_id::text AS "repositoryId", pipeline_id::text AS "pipelineId", scan_type AS "scanType",
          count(*) FILTER (WHERE decision = 'true_positive') AS "tpCount",
          count(*) FILTER (WHERE decision = 'false_positive') AS "fpCount",
          count(*) FILTER (WHERE suggestion IS NOT NULL) AS "withAdvisory",
          count(*) FILTER (WHERE suggestion = 'likely_false_positive' AND decision = 'false_positive') AS "agreeFp",
          count(*) FILTER (WHERE suggestion = 'likely_true_positive' AND decision = 'true_positive') AS "agreeTp",
          count(*) FILTER (WHERE suggestion = 'likely_false_positive' AND decision = 'true_positive') AS "advisoryFpHumanTp",
          count(*) FILTER (WHERE suggestion = 'likely_true_positive' AND decision = 'false_positive') AS "advisoryTpHumanFp",
          count(*) FILTER (WHERE suggestion = 'uncertain') AS "advisoryUncertain",
          count(*) FILTER (WHERE confidence >= 80 AND (
            (suggestion = 'likely_false_positive' AND decision = 'true_positive')
            OR (suggestion = 'likely_true_positive' AND decision = 'false_positive'))) AS "overrideConfident"
        FROM dec
        WHERE k BETWEEN 1 AND ${days.length}::int
        GROUP BY k, workspace_id, repository_id, pipeline_id, scan_type
        ORDER BY k, pipeline_id, scan_type`,
    );
    return rows.map((r) => ({
      tenantId,
      workspaceId: r.workspaceId,
      repositoryId: r.repositoryId,
      pipelineId: r.pipelineId,
      day: day(days, r.k),
      scanType: r.scanType,
      tpCount: num(r.tpCount),
      fpCount: num(r.fpCount),
      withAdvisory: num(r.withAdvisory),
      agreeFp: num(r.agreeFp),
      agreeTp: num(r.agreeTp),
      advisoryFpHumanTp: num(r.advisoryFpHumanTp),
      advisoryTpHumanFp: num(r.advisoryTpHumanFp),
      advisoryUncertain: num(r.advisoryUncertain),
      overrideConfident: num(r.overrideConfident),
    }));
  };
}

/**
 * SBOM components per day (S-8): the components of each pipeline's latest SBOM result, attributed to the tenant-local day the result was
 * created. The view holds ONLY the latest result of a pipeline, so an older result is not recoverable (the series is complete only from the
 * first live run); `components_vulnerable` counts the components with an open SCA finding of the same pipeline and purl AT COMPUTATION TIME.
 * @param {any} db @returns {(args: { tenantId: string, from: string, to: string, timeZone: string }) => Promise<any[]>}
 */
export function buildComputeSbomDays(db) {
  return async function computeSbomDays({ tenantId, from, to, timeZone }) {
    assertUuid(tenantId, "tenantId");
    const { days, thresholds, start, endExclusive } = dayThresholds(from, to, timeZone);
    const open = [...OPEN_FINDING_STATUSES];
    const rows = await inTransaction(
      db,
      (tx) => tx.$queryRaw`
        WITH comp AS (
          SELECT s.workspace_id, s.repository_id, s.pipeline_id, s.component_purl,
            width_bucket(EXTRACT(EPOCH FROM s.result_created_at)::float8, ${thresholds}::float8[]) AS k
          FROM report_sbom_latest_v s
          WHERE s.tenant_id = ${tenantId}::uuid AND s.result_created_at >= ${start}::timestamptz AND s.result_created_at < ${endExclusive}::timestamptz
        ),
        vuln AS (
          SELECT DISTINCT f.pipeline_id, f.component_purl
          FROM report_findings_v f
          WHERE f.tenant_id = ${tenantId}::uuid AND f.scan_type::text = 'sca' AND f.status::text = ANY(${open}::text[])
            AND f.component_purl IS NOT NULL
        )
        SELECT c.k::int AS k, c.workspace_id::text AS "workspaceId", c.repository_id::text AS "repositoryId", c.pipeline_id::text AS "pipelineId",
          count(*) AS components, count(v.component_purl) AS "componentsVulnerable"
        FROM comp c
        LEFT JOIN vuln v ON v.pipeline_id = c.pipeline_id AND v.component_purl = c.component_purl
        WHERE c.k BETWEEN 1 AND ${days.length}::int
        GROUP BY c.k, c.workspace_id, c.repository_id, c.pipeline_id
        ORDER BY c.k, c.pipeline_id`,
    );
    return rows.map((r) => ({
      tenantId,
      workspaceId: r.workspaceId,
      repositoryId: r.repositoryId,
      pipelineId: r.pipelineId,
      day: day(days, r.k),
      components: num(r.components),
      componentsVulnerable: num(r.componentsVulnerable),
    }));
  };
}
