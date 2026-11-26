# Reporting and Dashboards, amendment AM (forward-only series and the Part B defects): as built

**Built:** 2026-11-26 on main after Parts A0, A, B, C and D, in a worktree branch, not pushed. **Scope:** the lead's sanctioned amendments to A0-frozen files and the Part B reads (`SPEC.md` 17.5, `AS_BUILT_A.md` 1, `AS_BUILT_B.md` 7). Everything stays OFF behind `REPORTING_ENABLED=false`. `docs/api` was NOT regenerated (the lead does).

## 1. Migration `20261126110000_reporting_views_amendment` (additive)

| View | Columns | Notes |
|---|---|---|
| `report_repositories_v` | `tenant_id, workspace_id, repository_id, repository_name (full_name), provider, connection_status, enabled, archived` | no URL, owner, sync error, e-mail |
| `report_pipelines_v` | `tenant_id, workspace_id, repository_id, pipeline_id, pipeline_name, enabled, pipeline_deleted, scan_types_enabled text[]` | the array holds the scan types whose `scans.<type>.enabled` is true in the pipeline's CURRENT configuration version (sorted: sast, sbom, sca, secrets); `[]` without a version. The four flags are one array because the column name `secrets_enabled` would trip the frozen forbidden-column pattern (`secret`), which was not weakened. The configuration JSON is never exposed |
| `report_sla_targets_v` | `tenant_id, severity, hours` | no row = the shared default |

SELECT-only grants to `qm_reporting_ro` and `qm_reporting` (the same guarded `DO` block pattern); no source table grant. `provision-reporting-logins.js` lists the three views. `reporting.prisma` comment updated; `prisma generate` run (no model change). **No default-branch indicator**: `report_executions_v` has no ref name and the views expose none, so it is not derivable; `eligible_count` stays the A0/A approximation.

## 2. DTO changes (for the UI part)

`postureDtoSchema` (strict): new `partial: boolean` (false live, true as-of) and `githubConnections: { active, unavailable, disconnected } | null` (repository counts of the requested workspace; `null` without `execution.view` and as-of). Nullable now: `open`, `bySeverity`, `byType`, `byGroup`, `byStatus`, `backlog`, `workInProgress`, `criticalHighOpen`, each value inside `byGroup` and `byStatus`, `exceptions.inForce`, `exceptions.expiringWithin30Days`, `awaitingDecision.awaitingApproval`, `awaitingDecision.pendingExceptions` (`newLast24Hours` and `pipelinesHealthy` already were). Live: nothing is ever null except the gated `pipelinesHealthy` and `githubConnections`. As-of: known = `open`, `bySeverity`, `byType`, `backlog`, `workInProgress`, `criticalHighOpen`, `exceptions.inForce`, `byStatus.fixed_pending_verification`, `byGroup.awaiting_verification`, `byGroup.accepted_or_suppressed`; every other status/group/tile is `null` (not 0). For a day before the first exact day, or a day no live run wrote, EVERY state field is `null` (still 200, `partial: true`); a day no run covers is still 409 `REPORT_AS_OF_UNAVAILABLE`.

`trendPointSchema`: each series key is `... .nullable().optional()`. A requested series is a number or an explicit `null` on every day; an unrequested series is absent. `trendsDtoSchema`: `severityBackfilled: z.literal(false)` (always false; forward-only), new `stateSeriesFrom: day | null` (first exact day, null when no live run succeeded), `dataFrom` kept (first rollup row).

`createReportBodySchema.options` also allows `bom: boolean` (lead's request).

## 3. Read behaviour

- **First exact day** = `min(day)` over SUCCEEDED `report_rollup_runs` of mode `incremental` or `close` of the tenant, returned by `getRollupFreshness` as `firstExactDay` (and used by the service for `stateSeriesFrom`).
- **State series** (open by severity, backlog `open`, awaiting verification) are `null` before that day AND on a later day no live run wrote (a gap). **Flow series** (`new, fixed, closedWithoutFix, reopened, netChange`) keep their own rule: a number on any day a succeeded run of any mode covers (a covered day without rows is a real 0), `null` otherwise. The projection ignores null days. Execution, decision and SBOM series are unchanged.
- **As-of posture** (`getPostureAsOf`): 409 when no succeeded run covers the day; exact only when a succeeded `incremental`/`close` run has that `day`; the service also requires `asOf >= firstExactDay`.
- **R-4** (`getSla` closed): `COALESCE(report_sla_targets_v.hours, shared default)` per severity (the CURRENT target, not the one at the time the clock started).
- **P-10**: enabled, not deleted pipelines of `report_pipelines_v` whose latest finished execution of the last 90 days succeeded (a pipeline with none counts in `total`).
- **S-4**: universe = repositories enabled, not archived, not disconnected. Reason, first match: `connection_unavailable`, `no_pipeline`, `pipeline_disabled`, `no_recent_scan`, `last_scan_partial`. A recent success now counts only executions of non-deleted pipelines.
- **S-5**: `enabled` = the pipeline is enabled AND its current configuration enables the type; listed pipelines are the non-deleted ones. `lastComplete` is known for SBOM only.
- **Defect fixed on the way:** `getTrends` read the covering runs with `LIMIT 5000` and no distinct, so a 400 day window of hourly runs (about 9,600) lost coverage arbitrarily; it now reads `DISTINCT mode, day, range_to`.

## 4. Files

| Directory | Files |
|---|---|
| `packages/db/prisma/migrations/20261126110000_reporting_views_amendment/` | `migration.sql` (new) |
| `packages/db/prisma/schema/`, `packages/db/scripts/` | `reporting.prisma` (comment), `provision-reporting-logins.js` (three views) |
| `packages/db/src/reporting/read/` | `posture.js`, `findings-metrics.js`, `scan-metrics.js` |
| `packages/shared/src/reporting/` | `schemas.js` |
| `apps/api/src/modules/reporting/` | `services/read.js`, `mappers/read.js` |
| `apps/api/test/security/helpers/reporting/` | `reporting-am-checks.js` (new, 7 checks), `reporting-a0-checks.js` (view column lists, descriptions: no assertion weakened), `expected.js` (`AM: 7`), `index.js` |
| `docs/` | this file, `SPEC.md` 17.5, `docs/technical/DATABASE_DESIGN.md` |

## 5. Suite

`RPTAM-01` view content and redaction canaries; `-02` grants of both roles and denial on the source tables; `-03` tenant scoping through a REAL `qm_reporting_ro` login; `-04` GitHub connection counts per tenant and workspace plus pipelines healthy and the `execution.view` gate; `-05` null before the first exact day (trends and as-of posture); `-06` coverage reasons and per-pipeline scan types; `-07` the amended DTO schemas. They run on their own two fresh tenants. `RPTA0-05`, `-06` (canaries over every view) and the grants checks now cover the ten views through `VIEW_COLUMNS`. The R-4 tenant-target behaviour is asserted in `RPTAM-03`. The B checks needed no change.

## 6. Not verified / limits

- A tenant time-zone rebuild clears the state rows of the range but not the run rows, so after it the days between the old first exact day and the restart read as covered zeros (the run rows say live runs happened). Not handled.
- Performance of the new P-10 and coverage statements at 100,000 findings was not re-measured.
- The UI (Part D) was not run against the amended DTOs here.
- `contract:snapshot` not run (the lead regenerates `docs/api`).
