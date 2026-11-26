import {
  BACKLOG_STATUSES,
  EXCEPTION_IN_FORCE_STATUSES,
  OPEN_FINDING_STATUSES,
  SLA_DUE_SOON_FRACTION,
  SLA_STOPPED_STATUSES,
  WORK_IN_PROGRESS_STATUSES,
} from "@qmentisai/shared";
import { RollupInputError, assertUuid, inTransaction, num } from "./util.js";

/**
 * THE "state of the findings as of instant T" computation (docs/modules/reporting-dashboards/SPEC.md 7.2, ADR-015 item 3). Every consumer
 * (the hourly run, the day close, the equivalence tests) calls this one function.
 *
 *  - status at T = the latest `report_status_events_v` row of each finding with `created_at <= T`; a finding with no row at T does not
 *    exist at T;
 *  - the counters use the LIFECYCLE groups of `@qmentisai/shared` (open = backlog + work in progress, awaiting verification inside work in
 *    progress), grouped by (workspace, repository, pipeline, scan type, severity);
 *  - SLA states at T: an open finding that is not in an SLA-stopped status and has a stored `sla_due_at`: `breached` when T is after the due
 *    date, `due_soon` when the time left is at most the due-soon fraction of the target (`due - sla_started_at`), else `on_track`;
 *  - exceptions in force at T: status at T is `accepted_risk` or `suppressed` and an exception decided at or before T is neither ended nor
 *    expired at T (the review and exception timeline of `report_decisions_v`);
 *  - `open_age_seconds_sum`: whole seconds from `first_detected_at` to T over the open findings.
 *
 * SEVERITY AS OF T IS NOT RECONSTRUCTABLE FROM THE VIEWS (proved by RPT-S10): the effective severity changes through an approved review
 * override (visible in `report_decisions_v`, but only the NEW value) AND through a tool re-rate on recurrence, which leaves no trace at all.
 * The view carries only the CURRENT severity, so this function labels each finding with its current severity and reports, per row,
 * `severityExact`: true only when no approved review override was decided after T. Even then a past T is certified only for T = now (no
 * invisible re-rate can have happened since). The callers therefore write state rows only from a LIVE run (see `handler.js`): the severity
 * series is FORWARD-ONLY. The counts that do not depend on severity (status groups, totals) ARE exact at any T.
 */

/** @typedef {{ tenantId: string, instant: Date, workspaceId?: string }} StateArgs */

/**
 * @param {any} db the worker client
 * @returns {(args: StateArgs) => Promise<any[]>}
 */
export function buildComputeFindingsStateAsOf(db) {
  return async function computeFindingsStateAsOf({ tenantId, instant, workspaceId }) {
    assertUuid(tenantId, "tenantId");
    if (workspaceId !== undefined) assertUuid(workspaceId, "workspaceId");
    if (!(instant instanceof Date) || Number.isNaN(instant.getTime()))
      throw new RollupInputError("invalid_range", "instant is not a date");
    const ws = workspaceId ?? null;
    const open = [...OPEN_FINDING_STATUSES];
    const backlog = [...BACKLOG_STATUSES];
    const wip = [...WORK_IN_PROGRESS_STATUSES];
    const stopped = [...SLA_STOPPED_STATUSES];
    const exc = [...EXCEPTION_IN_FORCE_STATUSES];
    const soon = SLA_DUE_SOON_FRACTION;
    const { rows, newest } = await inTransaction(db, async (tx) => {
      const rows = await tx.$queryRaw`
        WITH last AS (
          SELECT DISTINCT ON (e.finding_id) e.finding_id, e.to_status::text AS status
          FROM report_status_events_v e
          WHERE e.tenant_id = ${tenantId}::uuid AND e.created_at <= ${instant}::timestamptz
            AND (${ws}::uuid IS NULL OR e.workspace_id = ${ws}::uuid)
          ORDER BY e.finding_id, e.rev DESC
        ),
        in_force AS (
          SELECT DISTINCT d.finding_id
          FROM report_decisions_v d
          WHERE d.tenant_id = ${tenantId}::uuid AND d.source = 'exception'
            AND d.state IN ('approved', 'expired', 'revoked', 'invalidated')
            AND d.decided_at <= ${instant}::timestamptz
            AND (d.expires_at IS NULL OR d.expires_at > ${instant}::timestamptz)
            AND (d.ended_at IS NULL OR d.ended_at > ${instant}::timestamptz)
        ),
        later_override AS (
          SELECT DISTINCT d.finding_id
          FROM report_decisions_v d
          WHERE d.tenant_id = ${tenantId}::uuid AND d.source = 'review' AND d.state = 'approved'
            AND d.severity_override IS NOT NULL AND d.decided_at > ${instant}::timestamptz
        ),
        base AS (
          SELECT f.workspace_id, f.repository_id, f.pipeline_id, f.scan_type::text AS scan_type, f.severity::text AS severity,
            (l.status = ANY(${open}::text[])) AS is_open,
            (l.status = ANY(${backlog}::text[])) AS is_backlog,
            (l.status = ANY(${wip}::text[])) AS is_wip,
            (l.status = 'fixed_pending_verification') AS is_awaiting,
            (l.status = ANY(${exc}::text[]) AND x.finding_id IS NOT NULL) AS is_exception,
            (l.status = ANY(${open}::text[]) AND NOT (l.status = ANY(${stopped}::text[]))
              AND f.sla_due_at IS NOT NULL AND f.sla_started_at IS NOT NULL) AS has_clock,
            f.sla_due_at, f.sla_started_at, f.first_detected_at,
            (o.finding_id IS NULL) AS sev_exact
          FROM last l
          JOIN report_findings_v f ON f.tenant_id = ${tenantId}::uuid AND f.id = l.finding_id
          LEFT JOIN in_force x ON x.finding_id = l.finding_id
          LEFT JOIN later_override o ON o.finding_id = l.finding_id
        )
        SELECT workspace_id::text AS "workspaceId", repository_id::text AS "repositoryId", pipeline_id::text AS "pipelineId",
          scan_type AS "scanType", severity,
          count(*) FILTER (WHERE is_open) AS "openCount",
          count(*) FILTER (WHERE is_backlog) AS "backlogCount",
          count(*) FILTER (WHERE is_wip) AS "wipCount",
          count(*) FILTER (WHERE is_awaiting) AS "awaitingVerificationCount",
          count(*) FILTER (WHERE has_clock AND ${instant}::timestamptz > sla_due_at) AS "slaBreached",
          count(*) FILTER (WHERE has_clock AND ${instant}::timestamptz <= sla_due_at
            AND EXTRACT(EPOCH FROM (sla_due_at - sla_started_at)) > 0
            AND EXTRACT(EPOCH FROM (sla_due_at - ${instant}::timestamptz)) <= ${soon}::float8 * EXTRACT(EPOCH FROM (sla_due_at - sla_started_at))) AS "slaDueSoon",
          count(*) FILTER (WHERE has_clock) AS "clockCount",
          count(*) FILTER (WHERE is_exception) AS "exceptionsInForce",
          COALESCE(sum(FLOOR(GREATEST(0, EXTRACT(EPOCH FROM (${instant}::timestamptz - first_detected_at)))))
            FILTER (WHERE is_open), 0)::bigint AS "openAgeSecondsSum",
          bool_and(sev_exact) AS "severityExact"
        FROM base
        GROUP BY workspace_id, repository_id, pipeline_id, scan_type, severity
        HAVING count(*) FILTER (WHERE is_open OR is_exception) > 0
        ORDER BY pipeline_id, scan_type, severity`;
      const newest = await tx.$queryRaw`
        SELECT e.id::text AS id FROM report_status_events_v e
        WHERE e.tenant_id = ${tenantId}::uuid AND e.created_at <= ${instant}::timestamptz
          AND (${ws}::uuid IS NULL OR e.workspace_id = ${ws}::uuid)
        ORDER BY e.created_at DESC, e.rev DESC, e.id DESC LIMIT 1`;
      return { rows, newest };
    });
    const out = rows.map((r) => {
      const clock = num(r.clockCount);
      const breached = num(r.slaBreached);
      const dueSoon = num(r.slaDueSoon);
      return {
        tenantId,
        workspaceId: r.workspaceId,
        repositoryId: r.repositoryId,
        pipelineId: r.pipelineId,
        scanType: r.scanType,
        severity: r.severity,
        openCount: num(r.openCount),
        backlogCount: num(r.backlogCount),
        wipCount: num(r.wipCount),
        awaitingVerificationCount: num(r.awaitingVerificationCount),
        slaOnTrack: clock - breached - dueSoon,
        slaDueSoon: dueSoon,
        slaBreached: breached,
        exceptionsInForce: num(r.exceptionsInForce),
        openAgeSecondsSum: num(r.openAgeSecondsSum),
        severityExact: r.severityExact === true,
      };
    });
    // "data as of": the newest history row read (the run row stores it); a property of the array, not a row field
    Object.defineProperty(out, "asOfHistoryId", {
      value: newest[0]?.id ?? null,
      enumerable: false,
    });
    return out;
  };
}
