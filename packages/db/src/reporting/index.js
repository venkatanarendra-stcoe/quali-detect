import { defineRepository } from "./not-implemented.js";
import { buildExportMethods, buildExportWorkerMethods } from "./exports/index.js";
import { buildReadMethods } from "./read/index.js";
import { buildRollupMethods } from "./rollup/index.js";

export * from "./not-implemented.js";

/**
 * Reporting data access (docs/modules/reporting-dashboards/SPEC.md 8, 12, 18; ADR-015). Part A0 FROZE the method names and JSDoc signatures
 * below; each part fills the bodies in its own directory and NEVER edits this file:
 *  - `rollup/index.js`  (Part A) exports `buildRollupMethods({ db })` returning the methods it has written;
 *  - `read/index.js`    (Part B) exports `buildReadMethods({ db })`;
 *  - `exports/index.js` (Part C) exports `buildExportMethods({ db })` (API side) and `buildExportWorkerMethods({ db })` (worker side).
 * A method that is not written yet rejects with `ReportingNotImplementedError`; a method outside the frozen names is refused at
 * construction.
 *
 * Which database client each factory takes (the ROLE decides what is possible, SPEC 12 item 7):
 *  - `createReportingRollupRepository`      the WORKER client (login member of `qm_reporting`; `REPORTING_DATABASE_URL`);
 *  - `createReportingReadRepository`        the API READ client (login member of `qm_reporting_ro`; `REPORTING_RO_DATABASE_URL`);
 *  - `createReportingExportsRepository`     the API's normal client (it creates the `report_exports` row and the outbox row in ONE transaction);
 *  - `createReportingExportWorkerRepository` the WORKER client (`qm_reporting`): claims and completes a run and reads ONLY the `report_*_v` views.
 * Every method takes `tenantId` (from the session or the verified message, NEVER from a body) and scopes by it; a workspace, repository or
 * pipeline id is always validated together with the tenant. Methods return plain rows (camelCase), never Prisma models.
 *
 * @typedef {string} Uuid
 * @typedef {string} DayString a tenant-local calendar day `YYYY-MM-DD`
 * @typedef {{ tenantId: Uuid, workspaceId: Uuid, repositoryId: Uuid, pipelineId: Uuid }} PipelineChain
 * @typedef {PipelineChain & { day: DayString, scanType: string, severity: string, openCount: number, backlogCount: number, wipCount: number, awaitingVerificationCount: number, slaOnTrack: number, slaDueSoon: number, slaBreached: number, exceptionsInForce: number, openAgeSecondsSum: number, newCount: number, fixedCount: number, closedOtherCount: number, reopenedCount: number }} FindingsDayRow a `report_daily_findings` row
 * @typedef {PipelineChain & { day: DayString, total: number, succeededCount: number, failedCount: number, partialCount: number, timedOutCount: number, cancelledCount: number, skippedCount: number, blockedCount: number, durationMsSum: number, queueWaitMsSum: number, eligibleCount: number, resultCompleteCount: number, resultPartialCount: number }} ExecutionsDayRow a `report_daily_executions` row
 * @typedef {PipelineChain & { day: DayString, scanType: string, tpCount: number, fpCount: number, withAdvisory: number, agreeFp: number, agreeTp: number, advisoryFpHumanTp: number, advisoryTpHumanFp: number, advisoryUncertain: number, overrideConfident: number }} DecisionsDayRow a `report_daily_decisions` row
 * @typedef {PipelineChain & { day: DayString, components: number, componentsVulnerable: number }} SbomDayRow a `report_daily_sbom` row
 * @typedef {{ id: Uuid, tenantId: Uuid, day: DayString, rangeTo: DayString | null, mode: string, status: string, startedAt: Date, finishedAt: Date | null, rowsWritten: number, errorCode: string | null, asOfHistoryId: Uuid | null, timeZone: string }} RollupRun
 * @typedef {{ id: Uuid, tenantId: Uuid, workspaceId: Uuid | null, template: string, format: string, params: Record<string, unknown>, periodFrom: DayString | null, periodTo: DayString | null, asOfDay: DayString | null, status: string, errorCode: string | null, requestedByUserId: Uuid, createdAt: Date, startedAt: Date | null, finishedAt: Date | null, expiresAt: Date | null, objectKey: string | null, bytes: number | null, sha256: string | null, rowCount: number | null, deletedAt: Date | null }} ReportExportRow a `report_exports` row (internal: the DTO mapper hides `objectKey` and `sha256`)
 * @typedef {{ tenantId: Uuid, workspaceId: Uuid, timeZone: string }} ReadScope
 */

// ---- Part A: the rollup writer (worker role `qm_reporting`) ----------------------------------------------------------------------

/**
 * @typedef {object} ReportingRollupRepository
 * @property {(args: { tenantId: Uuid }) => Promise<{ tenantId: Uuid, status: string, timeZone: string } | null>} getTenantSettings the tenant's status and reporting time zone from `report_tenant_settings_v` (null for an unknown tenant)
 * @property {(args: { limit: number, afterTenantId?: Uuid }) => Promise<Array<{ tenantId: Uuid, timeZone: string }>>} listActiveTenants keyset page of active tenants (the hourly scheduler tick)
 * @property {(args: { tenantId: Uuid }) => Promise<PipelineChain[]>} listPipelineChains every (workspace, repository, pipeline) chain that has findings or executions in the views
 * @property {(args: { tenantId: Uuid }) => Promise<Date | null>} earliestHistoryAt the oldest `report_status_events_v` row (the first-enablement backfill start)
 * @property {(args: { tenantId: Uuid, mode: string, day: DayString, rangeTo?: DayString | null, timeZone: string, now: Date }) => Promise<RollupRun>} startRun inserts a `running` row (tenant-scoped)
 * @property {(args: { tenantId: Uuid, runId: Uuid, status: "succeeded" | "failed", rowsWritten: number, errorCode?: string | null, asOfHistoryId?: Uuid | null, now: Date }) => Promise<void>} finishRun
 * @property {(args: { tenantId: Uuid, mode?: string, status?: string }) => Promise<RollupRun | null>} findLatestRun the newest run (the "data as of" of the API)
 * @property {(args: { tenantId: Uuid, from: DayString, to: DayString, mode?: string }) => Promise<RollupRun[]>} listRuns runs touching a day range (backfill resume)
 * @property {(args: { tenantId: Uuid, instant: Date, workspaceId?: Uuid }) => Promise<FindingsDayRow[]>} computeFindingsStateAsOf THE one "state as of T" function: the latest history row per finding with `created_at <= instant`, severity in force at `instant` (counters of the state only; flow counters 0). `day` of the rows is not set by the caller
 * @property {(args: { tenantId: Uuid, from: DayString, to: DayString, timeZone: string }) => Promise<FindingsDayRow[]>} computeFindingsFlow the flow counters per tenant-local day from the status history (T-1)
 * @property {(args: { tenantId: Uuid, from: DayString, to: DayString, timeZone: string }) => Promise<ExecutionsDayRow[]>} computeExecutionsDays executions per tenant-local day (S-1, S-2, S-6, S-7)
 * @property {(args: { tenantId: Uuid, from: DayString, to: DayString, timeZone: string }) => Promise<DecisionsDayRow[]>} computeDecisionsDays decisions and advisory agreement per tenant-local day (Q-1 to Q-5)
 * @property {(args: { tenantId: Uuid, from: DayString, to: DayString, timeZone: string }) => Promise<SbomDayRow[]>} computeSbomDays latest SBOM counts per tenant-local day
 * @property {(args: { tenantId: Uuid, rows: FindingsDayRow[] }) => Promise<number>} upsertFindingsDays idempotent upsert by the primary key; rows are re-validated against the tenant
 * @property {(args: { tenantId: Uuid, rows: ExecutionsDayRow[] }) => Promise<number>} upsertExecutionsDays
 * @property {(args: { tenantId: Uuid, rows: DecisionsDayRow[] }) => Promise<number>} upsertDecisionsDays
 * @property {(args: { tenantId: Uuid, rows: SbomDayRow[] }) => Promise<number>} upsertSbomDays
 * @property {(args: { tenantId: Uuid, from: DayString, to: DayString }) => Promise<number>} clearRange removes the daily rows of the tenant in an inclusive day range (through `qm_reporting_clear_range`; the role has no DELETE); returns the rows removed
 * @property {(args: { rollupBefore: DayString, runsBefore: Date, exportsBefore: Date, limit: number }) => Promise<number>} purgeExpired the retention purge (through `qm_reporting_purge`); returns the rows removed
 */

export const REPORTING_ROLLUP_METHODS = Object.freeze([
  "getTenantSettings",
  "listActiveTenants",
  "listPipelineChains",
  "earliestHistoryAt",
  "startRun",
  "finishRun",
  "findLatestRun",
  "listRuns",
  "computeFindingsStateAsOf",
  "computeFindingsFlow",
  "computeExecutionsDays",
  "computeDecisionsDays",
  "computeSbomDays",
  "upsertFindingsDays",
  "upsertExecutionsDays",
  "upsertDecisionsDays",
  "upsertSbomDays",
  "clearRange",
  "purgeExpired",
]);

/**
 * @param {{ db: any }} deps the WORKER client (a login member of `qm_reporting`)
 * @returns {Readonly<ReportingRollupRepository>}
 */
export function createReportingRollupRepository({ db }) {
  return /** @type {any} */ (
    defineRepository("A", REPORTING_ROLLUP_METHODS, buildRollupMethods({ db }))
  );
}

// ---- Part B: the read API queries (read role `qm_reporting_ro`) -------------------------------------------------------------------

/**
 * Every read takes `{ tenantId, workspaceId }` first (the tenant from the session, the workspace validated by the authorization layer) and
 * returns the data of the matching DTO schema of `@qmentisai/shared` (`REPORTING_ROUTE_SCHEMAS`), before the mapper strips and shapes it.
 * Day ranges are tenant-local days; `start` and `endExclusive` are the instants of the half-open range from `resolvePeriod`.
 * @typedef {object} ReportingReadRepository
 * @property {(args: { tenantId: Uuid }) => Promise<{ timeZone: string }>} getTenantSettings the reporting time zone (UTC when none is set)
 * @property {(args: { tenantId: Uuid }) => Promise<{ lastSuccessAt: Date | null, firstDay: DayString | null, recomputing: boolean }>} getRollupFreshness `meta.asOf` and `meta.stale` of the rollup-backed endpoints
 * @property {(args: { tenantId: Uuid, workspaceId: Uuid, now: Date, includePipelines: boolean }) => Promise<Record<string, any>>} getPosture live P-1 to P-10 (`includePipelines` only for a caller with `execution.view`)
 * @property {(args: { tenantId: Uuid, workspaceId: Uuid, day: DayString }) => Promise<Record<string, any> | null>} getPostureAsOf the rollup-backed point-in-time posture (null before the rollup start)
 * @property {(args: { tenantId: Uuid, workspaceId: Uuid, from: DayString, to: DayString, series: string[] }) => Promise<Record<string, any>>} getTrends T-1 to T-5, sparse rows (the mapper zero-fills)
 * @property {(args: { tenantId: Uuid, workspaceId: Uuid, from: DayString, to: DayString, start: Date, endExclusive: Date }) => Promise<Record<string, any>>} getRemediation R-1 to R-3, R-7, R-8, velocity
 * @property {(args: { tenantId: Uuid, workspaceId: Uuid, start: Date, endExclusive: Date, now: Date }) => Promise<Record<string, any>>} getSla R-4 and R-5
 * @property {(args: { tenantId: Uuid, workspaceId: Uuid, now: Date }) => Promise<Record<string, any>>} getAging R-6 including the oldest ten
 * @property {(args: { tenantId: Uuid, workspaceId: Uuid, from: DayString, to: DayString, start: Date, endExclusive: Date }) => Promise<Record<string, any>>} getScanActivity S-1 to S-3, S-6, S-7
 * @property {(args: { tenantId: Uuid, workspaceId: Uuid, now: Date, windowDays: number }) => Promise<Record<string, any>>} getCoverage S-4 and S-5 with reasons
 * @property {(args: { tenantId: Uuid, workspaceId: Uuid, from: DayString, to: DayString }) => Promise<Record<string, any>>} getSbom S-8
 * @property {(args: { tenantId: Uuid, workspaceId: Uuid, from: DayString, to: DayString, start: Date, endExclusive: Date }) => Promise<Record<string, any>>} getQuality Q-1 to Q-6
 * @property {(args: { tenantId: Uuid, workspaceId: Uuid, by: string, limit: number, after?: Record<string, unknown> | null }) => Promise<{ items: any[], next: Record<string, unknown> | null }>} getBreakdown B-2, B-3, B-5 (keyset)
 * @property {(args: { tenantId: Uuid, workspaceId: Uuid, limit: number }) => Promise<Array<Record<string, any>>>} getTopRisk B-4 (the score is computed with `computeRiskScore`)
 * @property {(args: { tenantId: Uuid, workspaceId: Uuid, now: Date }) => Promise<Record<string, any>>} getWorkload B-6
 * @property {(args: { tenantId: Uuid, workspaceIds: Uuid[], from: DayString, to: DayString, start: Date, endExclusive: Date, limit: number }) => Promise<Record<string, any>>} getOverview B-1 over the ACCESSIBLE workspaces only (the caller passes exactly those)
 */

export const REPORTING_READ_METHODS = Object.freeze([
  "getTenantSettings",
  "getRollupFreshness",
  "getPosture",
  "getPostureAsOf",
  "getTrends",
  "getRemediation",
  "getSla",
  "getAging",
  "getScanActivity",
  "getCoverage",
  "getSbom",
  "getQuality",
  "getBreakdown",
  "getTopRisk",
  "getWorkload",
  "getOverview",
]);

/**
 * @param {{ db: any }} deps the API READ client (a login member of `qm_reporting_ro`)
 * @returns {Readonly<ReportingReadRepository>}
 */
export function createReportingReadRepository({ db }) {
  return /** @type {any} */ (
    defineRepository("B", REPORTING_READ_METHODS, buildReadMethods({ db }))
  );
}

// ---- Part C: export runs ----------------------------------------------------------------------------------------------------------

/**
 * The API side of an export (the API's normal client): the run row, its limits and its lifecycle reads. `createExport` is called inside the
 * caller's transaction (`tx`) together with the outbox row of `reporting.export.requested`.
 * @typedef {object} ReportingExportsRepository
 * @property {(args: { tenantId: Uuid, id: Uuid, workspaceId: Uuid | null, template: string, format: string, params: Record<string, unknown>, periodFrom: DayString | null, periodTo: DayString | null, asOfDay: DayString | null, requestedByUserId: Uuid, now: Date }, tx?: any) => Promise<ReportExportRow>} createExport inserts a `queued` row (`id` is generated by the caller so the outbox message id is known)
 * @property {(args: { tenantId: Uuid }, tx?: any) => Promise<number>} countActiveExports queued plus running exports of the tenant (cap 3)
 * @property {(args: { tenantId: Uuid, userId: Uuid, since: Date }, tx?: any) => Promise<number>} countExportsByUserSince requests of one user since an instant (cap 20 per hour)
 * @property {(args: { tenantId: Uuid, id: Uuid }) => Promise<ReportExportRow | null>} getExport by tenant AND id (never by id alone); deleted rows are returned with `deletedAt`
 * @property {(args: { tenantId: Uuid, workspaceId?: Uuid | null, requestedByUserId?: Uuid, status?: string, limit: number, after?: { createdAt: Date, id: Uuid } | null }) => Promise<{ items: ReportExportRow[], next: { createdAt: Date, id: Uuid } | null }>} listExports keyset, newest first, deleted rows excluded
 * @property {(args: { tenantId: Uuid, id: Uuid, now: Date }) => Promise<ReportExportRow | null>} softDeleteExport sets `deleted_at` (the file is purged by the worker); null when absent or already deleted
 */

export const REPORTING_EXPORT_METHODS = Object.freeze([
  "createExport",
  "countActiveExports",
  "countExportsByUserSince",
  "getExport",
  "listExports",
  "softDeleteExport",
]);

/**
 * @param {{ db: any }} deps the API's normal client
 * @returns {Readonly<ReportingExportsRepository>}
 */
export function createReportingExportsRepository({ db }) {
  return /** @type {any} */ (
    defineRepository("C", REPORTING_EXPORT_METHODS, buildExportMethods({ db }))
  );
}

/**
 * The worker side of an export (client of `qm_reporting`): claim, read the views, complete or fail, expire. Rows are always loaded by
 * tenant AND id; a tenant in the message body is ignored (the caller passes the verified envelope tenant).
 * @typedef {object} ReportingExportWorkerRepository
 * @property {(args: { tenantId: Uuid, id: Uuid, now: Date }) => Promise<ReportExportRow | null>} claimExport `queued` to `running` in one statement; null when it is not `queued` (a replay) or not this tenant's
 * @property {(args: { tenantId: Uuid, id: Uuid }) => Promise<ReportExportRow | null>} getExportForWorker
 * @property {(args: { tenantId: Uuid, template: string, workspaceId: Uuid | null, params: Record<string, unknown>, periodFrom: DayString | null, periodTo: DayString | null, asOfDay: DayString | null, timeZone: string }) => Promise<number>} countExportRows the exact row count of the template over the views (the cap check BEFORE any file is written)
 * @property {(args: { tenantId: Uuid, template: string, workspaceId: Uuid | null, params: Record<string, unknown>, periodFrom: DayString | null, periodTo: DayString | null, asOfDay: DayString | null, timeZone: string, after?: Record<string, unknown> | null, limit: number }) => Promise<{ rows: Array<Record<string, any>>, next: Record<string, unknown> | null }>} readExportPage a keyset page of the template's rows from the `report_*_v` views ONLY
 * @property {(args: { tenantId: Uuid, id: Uuid, objectKey: string, bytes: number, sha256: string, rowCount: number | null, expiresAt: Date, now: Date }) => Promise<boolean>} completeExport `running` to `ready` (false when it is no longer `running`)
 * @property {(args: { tenantId: Uuid, id: Uuid, errorCode: string, now: Date }) => Promise<boolean>} failExport `running` (or `queued`) to `failed` with a stable code
 * @property {(args: { now: Date, limit: number }) => Promise<Array<{ tenantId: Uuid, id: Uuid, objectKey: string }>>} expireExports marks `ready` rows past `expires_at` (and deleted ones) `expired` and returns the file keys to purge
 */

export const REPORTING_EXPORT_WORKER_METHODS = Object.freeze([
  "claimExport",
  "getExportForWorker",
  "countExportRows",
  "readExportPage",
  "completeExport",
  "failExport",
  "expireExports",
]);

/**
 * @param {{ db: any }} deps the WORKER client (a login member of `qm_reporting`)
 * @returns {Readonly<ReportingExportWorkerRepository>}
 */
export function createReportingExportWorkerRepository({ db }) {
  return /** @type {any} */ (
    defineRepository("C", REPORTING_EXPORT_WORKER_METHODS, buildExportWorkerMethods({ db }))
  );
}
