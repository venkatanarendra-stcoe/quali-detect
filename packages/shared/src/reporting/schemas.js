import { z } from "zod";
import { FINDING_SCAN_TYPES, FINDING_SEVERITIES, FINDING_STATUSES } from "../findings/constants.js";
import {
  BREAKDOWN_DIMENSIONS,
  COVERAGE_REASONS,
  LIFECYCLE_GROUP_IDS,
  REPORT_FAILURE_CODES,
  REPORT_FORMATS,
  REPORT_MAX_PERIOD_DAYS,
  REPORT_PERIOD_PRESETS,
  REPORT_SOURCES,
  REPORT_STATUSES,
  REPORTING_LIMITS,
  TREND_SERIES,
} from "./constants.js";
import { isDayString, isValidTimeZone } from "./period.js";
import { REPORT_TEMPLATE_BY_ID } from "./templates.js";

/**
 * Zod contracts of the Reporting module (docs/modules/reporting-dashboards/SPEC.md 9; contract freeze Part A0). Query and body schemas are
 * `.strict()`: an unknown key is refused, and NO request ever carries `tenantId` (the tenant comes from the session). The overview takes
 * no `workspaceId` at all (a supplied one is a 400). Response schemas are strict too: a DTO holds counts, ids, enums and the explicitly
 * listed drill-down strings only, never a field of {@link FORBIDDEN_REPORTING_DTO_KEYS}. The message payload schemas live in
 * `@qmentisai/contracts` (`reporting.rollup.requested`, `reporting.export.requested`), the catalogue of message types.
 */

const uuid = z.string().uuid();
const iso = z.string().datetime({ offset: true });
const day = z.string().refine(isDayString, "must be a calendar day YYYY-MM-DD");
const count = z.number().int().min(0);
const num = z.number().finite();
const sev = z.enum(/** @type {[string, ...string[]]} */ ([...FINDING_SEVERITIES]));
const scanType = z.enum(/** @type {[string, ...string[]]} */ ([...FINDING_SCAN_TYPES]));

/** @param {z.ZodTypeAny} value @param {readonly string[]} keys */
const recordOf = (value, keys) =>
  z.object(Object.fromEntries(keys.map((k) => [k, value]))).strict();

const bySeverity = recordOf(count, FINDING_SEVERITIES);
const byScanType = recordOf(count, FINDING_SCAN_TYPES);
const byStatus = recordOf(count, FINDING_STATUSES);
const byGroup = recordOf(count, LIFECYCLE_GROUP_IDS);

// ---- Requests --------------------------------------------------------------------------------------------------------------

/** Keys that must NEVER appear in a reporting DTO (the suite greps every response for them, RPT-S03). */
export const FORBIDDEN_REPORTING_DTO_KEYS = Object.freeze([
  "tenantId",
  "tenant_id",
  "objectKey",
  "object_key",
  "sha256",
  "email",
  "evidence",
  "snippet",
  "rationale",
  "comment",
  "comments",
  "reasoning",
  "justification",
  "compensatingControls",
  "scmRef",
  "preview",
  "secretValue",
  "fingerprint",
  "correlationKey",
  "rawOutput",
  "prompt",
]);

/** `workspaceId` is a REQUIRED query parameter of every workspace read (the Findings pattern). */
export const workspaceQuerySchema = z.object({ workspaceId: uuid }).strict();

/** Period parameters: a preset (`7`, `30`, `90`) or `from` and `to` days, never both; resolved by `resolvePeriod`. */
const periodShape = {
  period: z
    .enum(/** @type {[string, ...string[]]} */ (REPORT_PERIOD_PRESETS.map(String)))
    .transform(Number)
    .optional(),
  from: day.optional(),
  to: day.optional(),
};
/** @param {z.ZodTypeAny} schema */
const periodRules = (schema) =>
  schema.superRefine((v, ctx) => {
    const hasRange = v.from !== undefined || v.to !== undefined;
    if (hasRange && (v.from === undefined || v.to === undefined || v.period !== undefined))
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        message: "REPORT_PERIOD_INVALID",
        params: { reason: "period_invalid" },
      });
    else if (hasRange && v.from > v.to)
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        message: "REPORT_PERIOD_INVALID",
        params: { reason: "period_invalid" },
      });
  });

export const workspacePeriodQuerySchema = periodRules(
  z.object({ workspaceId: uuid, ...periodShape }).strict(),
);

export const postureQuerySchema = z.object({ workspaceId: uuid, asOf: day.optional() }).strict();

export const trendsQuerySchema = periodRules(
  z
    .object({
      workspaceId: uuid,
      ...periodShape,
      series: z
        .string()
        .max(120)
        .optional()
        .transform((v) => (v === undefined ? [...TREND_SERIES] : v.split(",")))
        .refine(
          (a) => a.every((s) => TREND_SERIES.includes(s)) && new Set(a).size === a.length,
          "unknown series",
        ),
    })
    .strict(),
);

export const breakdownQuerySchema = periodRules(
  z
    .object({
      workspaceId: uuid,
      by: z.enum(/** @type {[string, ...string[]]} */ ([...BREAKDOWN_DIMENSIONS])),
      ...periodShape,
      limit: z.coerce.number().int().min(1).max(100).default(25),
      cursor: z.string().min(1).max(512).optional(),
    })
    .strict(),
);

export const topRiskQuerySchema = z
  .object({
    workspaceId: uuid,
    limit: z.coerce
      .number()
      .int()
      .min(1)
      .max(REPORTING_LIMITS.topRiskMaxLimit)
      .default(REPORTING_LIMITS.topRiskDefaultLimit),
  })
  .strict();

/** The Organization Overview: NO `workspaceId` and no tenant parameter (a supplied one is a 400 through `.strict()`). */
export const overviewQuerySchema = periodRules(z.object({ ...periodShape }).strict());

export const reportIdParamsSchema = z.object({ id: uuid }).strict();

export const listReportsQuerySchema = z
  .object({
    workspaceId: uuid.optional(),
    status: z.enum(/** @type {[string, ...string[]]} */ ([...REPORT_STATUSES])).optional(),
    limit: z.coerce.number().int().min(1).max(100).default(25),
    cursor: z.string().min(1).max(512).optional(),
  })
  .strict();

/**
 * `POST /reporting/reports` body (an `Idempotency-Key` header is required). `workspaceId` absent means a tenant-wide report. The
 * template decides which of `period` (a preset or `from`/`to`) or `asOfDay` is needed. `options` holds validated flags only, no free text.
 */
export const createReportBodySchema = z
  .object({
    template: z.string().min(1).max(64),
    format: z.enum(/** @type {[string, ...string[]]} */ ([...REPORT_FORMATS])),
    workspaceId: uuid.optional(),
    period: periodShape.period,
    from: day.optional(),
    to: day.optional(),
    asOfDay: day.optional(),
    options: z.object({ distinctIssues: z.boolean().optional() }).strict().optional(),
  })
  .strict()
  .superRefine((v, ctx) => {
    const bad = (reason, message) =>
      ctx.addIssue({ code: z.ZodIssueCode.custom, message, params: { reason } });
    const t = REPORT_TEMPLATE_BY_ID[v.template];
    if (!t || !t.v1) return bad("template_unknown", "REPORT_TEMPLATE_UNKNOWN");
    if (!t.formats.includes(/** @type {any} */ (v.format)))
      return bad("format_unsupported", "REPORT_TEMPLATE_UNKNOWN");
    const hasRange = v.from !== undefined || v.to !== undefined;
    const hasPeriod = hasRange || v.period !== undefined;
    if (hasRange && (v.from === undefined || v.to === undefined || v.period !== undefined))
      return bad("period_invalid", "REPORT_PERIOD_INVALID");
    if (t.periodMode === "period" && !hasPeriod)
      return bad("period_required", "REPORT_PERIOD_INVALID");
    if (t.periodMode !== "period" && hasPeriod)
      return bad("period_unexpected", "REPORT_PERIOD_INVALID");
    if (t.periodMode === "asOfDay" && v.asOfDay === undefined)
      return bad("as_of_required", "REPORT_PERIOD_INVALID");
    if (t.periodMode !== "asOfDay" && v.asOfDay !== undefined)
      return bad("as_of_unexpected", "REPORT_PERIOD_INVALID");
    if (v.workspaceId === undefined && !t.scopes.includes("tenant"))
      return bad("scope_unsupported", "REPORT_TEMPLATE_UNKNOWN");
  });

/** The tenant reporting time zone setting body (an IANA name; validated against the runtime). */
export const reportingTimezoneBodySchema = z
  .object({ timeZone: z.string().min(1).max(64).refine(isValidTimeZone, "not an IANA time zone") })
  .strict();

// ---- Response DTOs ----------------------------------------------------------------------------------------------------------

/** `meta` of every reporting response (SPEC 9), next to the envelope's `correlationId`. */
export const reportMetaSchema = z
  .object({
    asOf: iso,
    source: z.enum(/** @type {[string, ...string[]]} */ ([...REPORT_SOURCES])),
    stale: z.boolean(),
    timeZone: z.string().min(1).max(64),
    correlationId: z.string().max(100).optional(),
  })
  .strict();

/** `meta` of `GET /reporting/top-risk`: the printed formula. */
export const topRiskMetaSchema = reportMetaSchema.extend({ formula: z.string().max(300) }).strict();

const periodDtoSchema = z
  .object({
    from: day,
    to: day,
    dayCount: z.number().int().min(1).max(REPORT_MAX_PERIOD_DAYS),
    preset: z.number().int().nullable(),
  })
  .strict();

const stats = z
  .object({
    count,
    medianDays: num.nullable(),
    p90Days: num.nullable(),
    meanDays: num.nullable(),
  })
  .strict();

/** A rate that is not shown below the minimum sample (SPEC 5 rule 9): `rate` is null and `tooFew` true. */
const rate = z
  .object({
    numerator: count,
    denominator: count,
    rate: num.min(0).max(1).nullable(),
    tooFew: z.boolean(),
  })
  .strict();

export const postureDtoSchema = z
  .object({
    asOfDay: day.nullable(),
    open: count,
    bySeverity,
    byType: byScanType,
    byGroup,
    byStatus,
    backlog: count,
    workInProgress: count,
    criticalHighOpen: count,
    exceptions: z.object({ inForce: count, expiringWithin30Days: count }).strict(),
    awaitingDecision: z.object({ awaitingApproval: count, pendingExceptions: count }).strict(),
    newLast24Hours: count.nullable(),
    pipelinesHealthy: z.object({ healthy: count, total: count }).strict().nullable(),
  })
  .strict();

export const trendPointSchema = z
  .object({
    day,
    new: count.optional(),
    fixed: count.optional(),
    closedWithoutFix: count.optional(),
    reopened: count.optional(),
    openBySeverity: bySeverity.optional(),
    open: count.optional(),
    netChange: z.number().int().optional(),
    awaitingVerification: count.optional(),
  })
  .strict();

export const trendsDtoSchema = z
  .object({
    period: periodDtoSchema,
    points: z.array(trendPointSchema).max(REPORT_MAX_PERIOD_DAYS),
    /** Backfilled severity series exist only when the equivalence proof held (ADR-015 item 3); false means forward-only. */
    severityBackfilled: z.boolean(),
    /** The first day with a rollup row; days before it carry no data (not zero). */
    dataFrom: day.nullable(),
    recomputing: z.boolean(),
    projection: z
      .object({
        days: z.array(z.object({ day, open: num.min(0) }).strict()),
        label: z.literal("estimate"),
      })
      .strict()
      .nullable(),
  })
  .strict();

export const remediationDtoSchema = z
  .object({
    period: periodDtoSchema,
    timeToRemediate: z
      .object({
        overall: stats,
        bySeverity: recordOf(stats, FINDING_SEVERITIES),
        reopenedThenFixed: count,
      })
      .strict(),
    velocity: z.array(z.object({ weekStart: day, fixed: count }).strict()),
    timeToFirstDecision: z
      .object({ overall: stats, byType: recordOf(stats, FINDING_SCAN_TYPES) })
      .strict(),
    verificationLag: stats,
    reopenRate: rate,
  })
  .strict();

const slaOpen = z.object({ onTrack: count, dueSoon: count, breached: count }).strict();
export const reportSlaDtoSchema = z
  .object({
    closed: recordOf(
      z
        .object({ withTarget: count, withinSla: count, compliance: num.min(0).max(1).nullable() })
        .strict(),
      FINDING_SEVERITIES.filter((s) => s !== "info"),
    ),
    open: z
      .object({
        bySeverity: recordOf(
          slaOpen,
          FINDING_SEVERITIES.filter((s) => s !== "info"),
        ),
        total: slaOpen,
      })
      .strict(),
  })
  .strict();

export const agingDtoSchema = z
  .object({
    buckets: z
      .array(z.object({ bucket: z.enum(["0-7", "8-30", "31-90", "90+"]), bySeverity }).strict())
      .length(4),
    oldest: z
      .array(
        z
          .object({
            id: uuid,
            title: z.string().max(500),
            severity: sev,
            ageDays: count,
            repositoryName: z.string().max(300).nullable(),
          })
          .strict(),
      )
      .max(REPORTING_LIMITS.agingOldestLimit),
  })
  .strict();

const execStatusCounts = z
  .object({
    succeeded: count,
    failed: count,
    partial: count,
    timed_out: count,
    cancelled: count,
    skipped: count,
    blocked: count,
  })
  .strict();

export const scanActivityDtoSchema = z
  .object({
    period: periodDtoSchema,
    perDay: z
      .array(z.object({ day, total: count, byStatus: execStatusCounts }).strict())
      .max(REPORT_MAX_PERIOD_DAYS),
    successRate: z
      .object({ numerator: count, denominator: count, rate: num.min(0).max(1).nullable() })
      .strict(),
    duration: z.object({ medianMs: num.nullable(), p90Ms: num.nullable() }).strict(),
    queueWait: z.object({ medianMs: num.nullable(), p90Ms: num.nullable() }).strict(),
    completeness: z.object({ complete: count, incomplete: count }).strict(),
    ingestionEligibleShare: z.object({ eligible: count, total: count }).strict(),
  })
  .strict();

export const reportCoverageDtoSchema = z
  .object({
    repositories: z.object({ covered: count, total: count }).strict(),
    uncovered: z
      .array(
        z
          .object({
            repositoryId: uuid,
            repositoryName: z.string().max(300),
            reason: z.enum(/** @type {[string, ...string[]]} */ ([...COVERAGE_REASONS])),
          })
          .strict(),
      )
      .max(500),
    pipelines: z
      .array(
        z
          .object({
            pipelineId: uuid,
            pipelineName: z.string().max(300),
            repositoryId: uuid,
            scanTypes: z.array(
              z
                .object({
                  type: z.enum(["sbom", "sca", "sast", "secrets"]),
                  enabled: z.boolean(),
                  lastComplete: z.boolean().nullable(),
                })
                .strict(),
            ),
          })
          .strict(),
      )
      .max(500),
  })
  .strict();

export const sbomDtoSchema = z
  .object({
    components: count,
    vulnerable: count,
    byEcosystem: z
      .array(z.object({ ecosystem: z.string().max(60), components: count }).strict())
      .max(100),
    trend: z
      .array(z.object({ day, components: count, vulnerable: count }).strict())
      .max(REPORT_MAX_PERIOD_DAYS),
  })
  .strict();

export const qualityDtoSchema = z
  .object({
    period: periodDtoSchema,
    falsePositiveRate: z
      .object({ overall: rate, byType: recordOf(rate, FINDING_SCAN_TYPES) })
      .strict(),
    noisyRules: z
      .array(
        z
          .object({
            ruleId: z.string().max(300),
            scanType: scanType,
            decisions: count,
            falsePositiveShare: num.min(0).max(1),
          })
          .strict(),
      )
      .max(10),
    advisoryCoverage: rate,
    advisoryAgreement: z
      .object({
        agreed: count,
        decided: count,
        rate: num.min(0).max(1).nullable(),
        tooFew: z.boolean(),
        matrix: z
          .object({
            advisoryFpHumanFp: count,
            advisoryTpHumanTp: count,
            advisoryFpHumanTp: count,
            advisoryTpHumanFp: count,
            advisoryUncertain: count,
          })
          .strict(),
      })
      .strict(),
    humanOverrideRate: rate,
    advisoryOutcomes: z
      .array(
        z
          .object({
            status: z.string().max(40),
            providerKind: z.string().max(40).nullable(),
            count,
          })
          .strict(),
      )
      .max(100),
  })
  .strict();

const breakdownRowSchema = z
  .object({
    key: z.string().max(300),
    label: z.string().max(300),
    deleted: z.boolean().optional(),
    open: count,
    bySeverity,
    slaBreached: count,
    share: num.min(0).max(1).optional(),
    lastScan: z
      .object({ status: z.string().max(40), at: iso })
      .strict()
      .nullable()
      .optional(),
  })
  .strict();
export const breakdownDtoSchema = z
  .object({
    by: z.enum(/** @type {[string, ...string[]]} */ ([...BREAKDOWN_DIMENSIONS])),
    items: z.array(breakdownRowSchema).max(100),
    nextCursor: z.string().max(512).nullable(),
  })
  .strict();

export const topRiskDtoSchema = z
  .object({
    items: z
      .array(
        z
          .object({
            repositoryId: uuid,
            repositoryName: z.string().max(300),
            score: count,
            critical: count,
            high: count,
            medium: count,
            low: count,
            breachedCriticalHigh: count,
          })
          .strict(),
      )
      .max(REPORTING_LIMITS.topRiskMaxLimit),
  })
  .strict();

export const workloadDtoSchema = z
  .object({
    assignees: z
      .array(
        z
          .object({
            user: z.object({ id: uuid, displayName: z.string().max(200) }).strict(),
            open: count,
            dueSoon: count,
            breached: count,
          })
          .strict(),
      )
      .max(500),
    unassigned: count,
  })
  .strict();

export const overviewDtoSchema = z
  .object({
    period: periodDtoSchema,
    workspaces: z
      .array(
        z
          .object({
            workspaceId: uuid,
            name: z.string().max(200),
            open: count.nullable(),
            bySeverity: bySeverity.nullable(),
            slaBreached: count.nullable(),
            executions: count.nullable(),
            successRate: num.min(0).max(1).nullable(),
          })
          .strict(),
      )
      .max(500),
    totals: z.object({ open: count, bySeverity, slaBreached: count }).strict(),
    topRisk: topRiskDtoSchema.shape.items,
  })
  .strict();

export const reportRunDtoSchema = z
  .object({
    id: uuid,
    template: z.string().max(64),
    format: z.enum(/** @type {[string, ...string[]]} */ ([...REPORT_FORMATS])),
    workspaceId: uuid.nullable(),
    status: z.enum(/** @type {[string, ...string[]]} */ ([...REPORT_STATUSES])),
    errorCode: z.enum(/** @type {[string, ...string[]]} */ ([...REPORT_FAILURE_CODES])).nullable(),
    period: z.object({ from: day, to: day }).strict().nullable(),
    asOfDay: day.nullable(),
    requestedBy: z.object({ id: uuid, displayName: z.string().max(200) }).strict(),
    createdAt: iso,
    startedAt: iso.nullable(),
    finishedAt: iso.nullable(),
    expiresAt: iso.nullable(),
    bytes: count.nullable(),
    rowCount: count.nullable(),
    canDownload: z.boolean(),
  })
  .strict();

export const createReportResponseSchema = z.object({ reportId: uuid }).strict();
export const listReportsDtoSchema = z
  .object({
    items: z.array(reportRunDtoSchema).max(100),
    nextCursor: z.string().max(512).nullable(),
  })
  .strict();

/** Route key to its `{ query | params | body, data, meta }` schemas: the frozen response contract of SPEC 9. */
export const REPORTING_ROUTE_SCHEMAS = Object.freeze({
  "GET /reporting/posture": {
    query: postureQuerySchema,
    data: postureDtoSchema,
    meta: reportMetaSchema,
  },
  "GET /reporting/trends": {
    query: trendsQuerySchema,
    data: trendsDtoSchema,
    meta: reportMetaSchema,
  },
  "GET /reporting/remediation": {
    query: workspacePeriodQuerySchema,
    data: remediationDtoSchema,
    meta: reportMetaSchema,
  },
  "GET /reporting/sla": {
    query: workspaceQuerySchema,
    data: reportSlaDtoSchema,
    meta: reportMetaSchema,
  },
  "GET /reporting/aging": {
    query: workspaceQuerySchema,
    data: agingDtoSchema,
    meta: reportMetaSchema,
  },
  "GET /reporting/scan-activity": {
    query: workspacePeriodQuerySchema,
    data: scanActivityDtoSchema,
    meta: reportMetaSchema,
  },
  "GET /reporting/coverage": {
    query: workspaceQuerySchema,
    data: reportCoverageDtoSchema,
    meta: reportMetaSchema,
  },
  "GET /reporting/sbom": {
    query: workspacePeriodQuerySchema,
    data: sbomDtoSchema,
    meta: reportMetaSchema,
  },
  "GET /reporting/quality": {
    query: workspacePeriodQuerySchema,
    data: qualityDtoSchema,
    meta: reportMetaSchema,
  },
  "GET /reporting/breakdown": {
    query: breakdownQuerySchema,
    data: breakdownDtoSchema,
    meta: reportMetaSchema,
  },
  "GET /reporting/top-risk": {
    query: topRiskQuerySchema,
    data: topRiskDtoSchema,
    meta: topRiskMetaSchema,
  },
  "GET /reporting/workload": {
    query: workspaceQuerySchema,
    data: workloadDtoSchema,
    meta: reportMetaSchema,
  },
  "GET /reporting/overview": {
    query: overviewQuerySchema,
    data: overviewDtoSchema,
    meta: reportMetaSchema,
  },
  "POST /reporting/reports": { body: createReportBodySchema, data: createReportResponseSchema },
  "GET /reporting/reports": { query: listReportsQuerySchema, data: listReportsDtoSchema },
  "GET /reporting/reports/{id}": { params: reportIdParamsSchema, data: reportRunDtoSchema },
  "GET /reporting/reports/{id}/download": { params: reportIdParamsSchema },
  "DELETE /reporting/reports/{id}": { params: reportIdParamsSchema },
});
