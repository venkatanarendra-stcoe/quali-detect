import { z } from "zod";
import {
  ADVISORY_DTO_STATUSES,
  ADVISORY_EGRESS_LEVELS,
  ADVISORY_SUGGESTIONS,
  EXCEPTION_KINDS,
  EXCEPTION_STATES,
  FINDING_ACTION_IDS,
  FINDING_CONFIDENCES,
  FINDING_KIND_VALUES,
  FINDINGS_LIMITS as L,
  FINDING_SCAN_TYPES,
  FINDING_SEVERITIES,
  FINDING_STATUSES,
  REVIEW_DECISIONS,
  SAVED_VIEW_IDS,
  SLA_STATES,
} from "./constants.js";
import { hasCredentialShape } from "./normalize.js";

/**
 * Zod contracts of the Findings module (docs/modules/findings/SPEC.md 8.1 to 8.3; contract freeze Part A0). Request bodies and
 * queries are `.strict()`: unknown keys are refused, and a body NEVER carries `tenantId`, `workspaceId`, `pipelineId`,
 * `fingerprint`, `status` or `reviewerId` (SPEC 8). A free-text field that looks like a credential is refused with the issue
 * `params.reason = "credential_shape"` (the controller maps it to `VALIDATION_FAILED` / `details.reason`).
 */

const uuid = z.string().uuid();
const iso = z.string().datetime({ offset: true });
const rev = z.number().int().min(0);
const sev = z.enum(/** @type {[string, ...string[]]} */ ([...FINDING_SEVERITIES]));
const status = z.enum(/** @type {[string, ...string[]]} */ ([...FINDING_STATUSES]));
const scanType = z.enum(/** @type {[string, ...string[]]} */ ([...FINDING_SCAN_TYPES]));
const suggestion = z.enum(/** @type {[string, ...string[]]} */ ([...ADVISORY_SUGGESTIONS]));

/** A plain-text field: trimmed, length bounded, no credential shape (`credential_shape`). @param {number} min @param {number} max */
const freeText = (min, max) =>
  z
    .string()
    .trim()
    .min(min)
    .max(max)
    .superRefine((v, ctx) => {
      if (hasCredentialShape(v))
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          message: "credential_shape",
          params: { reason: "credential_shape" },
        });
    });

// ---- Shared pieces --------------------------------------------------------------------------------------------------------

/** A user reference in a DTO: id and display name only, never an e-mail address. */
export const userRefSchema = z.object({ id: uuid, displayName: z.string().max(200) }).strict();

/** Comma separated list of enum values (`severity=critical,high`). @param {readonly string[]} values */
const csv = (values) =>
  z
    .string()
    .max(200)
    .transform((s) => s.split(",").filter((x) => x.length > 0))
    .pipe(
      z
        .array(z.enum(/** @type {[string, ...string[]]} */ ([...values])))
        .min(1)
        .max(values.length),
    );

const pagination = {
  page: z.coerce.number().int().min(1).max(100000).optional(),
  pageSize: z.coerce
    .number()
    .int()
    .refine((n) => L.pageSizes.includes(n), "pageSize")
    .optional(),
  cursor: z.string().min(1).max(2000).optional(),
  limit: z.coerce.number().int().min(1).max(L.maxLimit).optional(),
};
/** `page` (or `pageSize`) with `cursor` (or `limit`) is `400 VALIDATION_FAILED` (SPEC 8, Pagination). */
const noMixedPagination = (q, ctx) => {
  if (
    (q.page !== undefined || q.pageSize !== undefined) &&
    (q.cursor !== undefined || q.limit !== undefined)
  )
    ctx.addIssue({ code: z.ZodIssueCode.custom, message: "page and cursor cannot be combined" });
};

// ---- 8.1 Queries ----------------------------------------------------------------------------------------------------------

export const FINDING_SORTS = Object.freeze([
  "severity",
  "slaDueAt",
  "firstDetectedAt",
  "lastSeenAt",
  "title",
]);
export const FINDING_SORT_DIRECTIONS = Object.freeze(["asc", "desc"]);

const filterShape = {
  workspaceId: uuid,
  view: z.enum(/** @type {[string, ...string[]]} */ ([...SAVED_VIEW_IDS])).optional(),
  severity: csv(FINDING_SEVERITIES).optional(),
  status: csv(FINDING_STATUSES).optional(),
  scanType: csv(FINDING_SCAN_TYPES).optional(),
  pipelineId: uuid.optional(),
  repositoryId: uuid.optional(),
  assignee: z.union([z.enum(["me", "unassigned"]), uuid]).optional(),
  sla: csv(["on_track", "due_soon", "breached", "none"]).optional(),
  aiSuggestion: z.enum([...ADVISORY_SUGGESTIONS, "none"]).optional(),
  q: z.string().trim().min(L.queryMin).max(L.queryMax).optional(),
};

/** `GET /findings` */
export const listFindingsQuerySchema = z
  .object({
    ...filterShape,
    sort: z.enum(/** @type {[string, ...string[]]} */ ([...FINDING_SORTS])).optional(),
    direction: z.enum(["asc", "desc"]).optional(),
    ...pagination,
  })
  .strict()
  .superRefine(noMixedPagination);

/** `GET /findings/summary` */
export const summaryQuerySchema = z.object({ workspaceId: uuid }).strict();

/** `GET /findings/{id}/history` and `/comments` */
export const keysetQuerySchema = z
  .object({
    cursor: z.string().min(1).max(2000).optional(),
    limit: z.coerce.number().int().min(1).max(L.maxLimit).optional(),
  })
  .strict();

/** `GET /review-queue` (a subset of the list filters) */
export const reviewQueueQuerySchema = z
  .object({
    workspaceId: uuid,
    severity: filterShape.severity,
    scanType: filterShape.scanType,
    pipelineId: uuid.optional(),
    aiSuggestion: filterShape.aiSuggestion,
    q: filterShape.q,
    sort: z.enum(["oldest", "severity"]).optional(),
    ...pagination,
  })
  .strict()
  .superRefine(noMixedPagination);

/** `GET /approvals` */
export const approvalsQuerySchema = z
  .object({
    workspaceId: uuid,
    kind: z.enum(["review", "exception"]).optional(),
    severity: filterShape.severity,
    pipelineId: uuid.optional(),
    ...pagination,
  })
  .strict()
  .superRefine(noMixedPagination);

export const BOARD_COLUMNS = Object.freeze([
  "assigned",
  "in_remediation",
  "fixed_pending_verification",
  "verified_fixed",
  "reopened",
]);
const boardFilters = {
  workspaceId: uuid,
  assignee: filterShape.assignee,
  severity: filterShape.severity,
  pipelineId: uuid.optional(),
  sla: filterShape.sla,
};
/** `GET /remediation/board` */
export const boardQuerySchema = z.object(boardFilters).strict();
/** `GET /remediation/board/{column}` */
export const boardColumnQuerySchema = z
  .object({
    ...boardFilters,
    cursor: z.string().min(1).max(2000).optional(),
    limit: z.coerce.number().int().min(1).max(L.maxLimit).optional(),
  })
  .strict();
export const boardColumnParamsSchema = z
  .object({ column: z.enum(/** @type {[string, ...string[]]} */ ([...BOARD_COLUMNS])) })
  .strict();

/** Path parameters. */
export const findingParamsSchema = z.object({ id: uuid }).strict();
export const reviewParamsSchema = z.object({ id: uuid, reviewId: uuid }).strict();
export const exceptionParamsSchema = z.object({ id: uuid, exceptionId: uuid }).strict();

// ---- 8.2 Request bodies ---------------------------------------------------------------------------------------------------

const withRev = { expectedRev: rev };

export const claimBodySchema = z.object({ ...withRev }).strict();
export const createReviewBodySchema = z
  .object({
    decision: z.enum(/** @type {[string, ...string[]]} */ ([...REVIEW_DECISIONS])),
    rationale: freeText(L.rationaleMin, L.rationaleMax),
    severityOverride: sev.optional(),
    ...withRev,
  })
  .strict()
  .superRefine((b, ctx) => {
    if (b.severityOverride !== undefined && b.decision !== "true_positive")
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        message: "override_requires_tp",
        params: { reason: "override_requires_tp" },
        path: ["severityOverride"],
      });
  });
export const withdrawReviewBodySchema = z.object({ ...withRev }).strict();
export const approveBodySchema = z
  .object({ comment: freeText(1, L.approvalCommentMax).optional(), ...withRev })
  .strict();
/** Rejection needs a comment (SPEC RV-2, SM-7). */
export const rejectBodySchema = z
  .object({ comment: freeText(1, L.approvalCommentMax), ...withRev })
  .strict();
export const reopenReviewBodySchema = z.object({ reason: freeText(1, 500), ...withRev }).strict();
export const assignBodySchema = z
  .object({ assigneeUserId: uuid, note: freeText(1, L.assignmentNoteMax).optional(), ...withRev })
  .strict();
export const clearAssignmentBodySchema = z
  .object({ note: freeText(1, L.assignmentNoteMax).optional(), ...withRev })
  .strict();
export const remediationStartBodySchema = z.object({ ...withRev }).strict();

/** https only, no userinfo, at most 500 characters (RM-1). */
export const pullRequestUrlSchema = z
  .string()
  .max(L.pullRequestUrlMax)
  .refine((v) => {
    try {
      const u = new URL(v);
      return (
        u.protocol === "https:" && u.username === "" && u.password === "" && !hasCredentialShape(v)
      );
    } catch {
      return false;
    }
  }, "pull request URL must be https without credentials");
export const remediationSubmitBodySchema = z
  .object({
    pullRequestUrl: pullRequestUrlSchema.optional(),
    ticketKey: z
      .string()
      .regex(/^[A-Z][A-Z0-9]{1,9}-[0-9]{1,8}$/)
      .optional(),
    note: freeText(1, L.remediationNoteMax).optional(),
    ...withRev,
  })
  .strict();

export const createExceptionBodySchema = z
  .object({
    kind: z.enum(/** @type {[string, ...string[]]} */ ([...EXCEPTION_KINDS])),
    justification: freeText(L.justificationMin, L.justificationMax),
    compensatingControls: freeText(1, L.compensatingControlsMax).optional(),
    expiresAt: iso.optional(),
    requestedApproverUserId: uuid.optional(),
    ...withRev,
  })
  .strict()
  .superRefine((b, ctx) => {
    const bad = (path, reason) =>
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        message: reason,
        params: { reason },
        path: [path],
      });
    if (b.kind === "accept_risk" && b.expiresAt === undefined)
      bad("expiresAt", "expiry_out_of_range");
    if (b.kind === "suppress" && b.compensatingControls !== undefined)
      bad("compensatingControls", "expiry_out_of_range");
  });
export const withdrawExceptionBodySchema = z.object({}).strict();
export const exceptionApproveBodySchema = approveBodySchema;
export const exceptionRejectBodySchema = rejectBodySchema;
export const revokeExceptionBodySchema = z
  .object({ reason: freeText(1, 500), ...withRev })
  .strict();
export const createCommentBodySchema = z.object({ body: freeText(1, L.commentMax) }).strict();
export const advisoryRequestBodySchema = z.object({}).strict();
export const bulkClaimBodySchema = z
  .object({ workspaceId: uuid, findingIds: z.array(uuid).min(1).max(L.bulkMax) })
  .strict()
  .refine((b) => new Set(b.findingIds).size === b.findingIds.length, "duplicate finding id");
export const bulkAssignBodySchema = z
  .object({
    workspaceId: uuid,
    findingIds: z.array(uuid).min(1).max(L.bulkMax),
    assigneeUserId: uuid,
    note: freeText(1, L.assignmentNoteMax).optional(),
  })
  .strict()
  .refine((b) => new Set(b.findingIds).size === b.findingIds.length, "duplicate finding id");
/** `PUT /settings/findings-sla` */
export const putSlaBodySchema = z
  .object({
    targets: z
      .array(
        z.object({ severity: sev, hours: z.number().int().min(1).max(L.slaHoursMax) }).strict(),
      )
      .min(1)
      .max(4),
  })
  .strict()
  .refine(
    (b) => new Set(b.targets.map((t) => t.severity)).size === b.targets.length,
    "duplicate severity",
  )
  .refine((b) => b.targets.every((t) => t.severity !== "info"), "info has no target");

// ---- 8.3 DTOs -------------------------------------------------------------------------------------------------------------

/** Keys that must NEVER appear in a finding DTO (SPEC 8.3). The suite greps every response for them (FND-S12). */
export const FORBIDDEN_FINDING_DTO_KEYS = Object.freeze([
  "tenantId",
  "workspaceId",
  "correlationKey",
  "correlation_key",
  "executionId",
  "firstExecutionId",
  "lastSeenExecutionId",
  "lastSeenScanResultId",
  "scanResultId",
  "cloneUrl",
  "email",
  "rawOutput",
  "prompt",
  "rawResponse",
  "secretValue",
  "preview",
  "valueLength",
  "apiKey",
  "baseUrl",
]);

export const slaDtoSchema = z
  .object({
    state: z.enum(/** @type {[string, ...string[]]} */ ([...SLA_STATES])),
    dueAt: iso.nullable(),
    targetHours: z.number().int().nullable(),
  })
  .strict();

const pendingDecisionSchema = z
  .object({
    kind: z.enum(["review", "exception"]),
    decision: z.string().max(40).optional(),
    exceptionKind: z.enum(/** @type {[string, ...string[]]} */ ([...EXCEPTION_KINDS])).optional(),
    submittedAt: iso,
  })
  .strict();

export const advisoryHintSchema = z
  .object({ suggestion, confidence: z.number().int().min(0).max(100) })
  .strict();

/** One row of a list, a queue or a board column (SPEC 8.3). */
export const findingListItemSchema = z
  .object({
    id: uuid,
    title: z.string().max(L.titleMax),
    scanType,
    kind: z.enum(/** @type {[string, ...string[]]} */ ([...FINDING_KIND_VALUES])),
    ruleId: z.string().max(L.ruleIdMax),
    cwe: z.array(z.number().int()).max(10),
    severity: sev,
    toolSeverity: sev,
    severityOverridden: z.boolean(),
    status,
    claimedBy: userRefSchema.nullable(),
    location: z
      .object({
        path: z.string().max(L.pathMax).nullable(),
        startLine: z.number().int().nullable(),
        endLine: z.number().int().nullable(),
      })
      .strict(),
    component: z
      .object({
        name: z.string().max(200),
        version: z.string().max(100).nullable(),
        ecosystem: z.string().max(40),
      })
      .strict()
      .nullable(),
    pipeline: z.object({ id: uuid, name: z.string().max(200), deleted: z.boolean() }).strict(),
    repository: z.object({ id: uuid, fullName: z.string().max(300) }).strict(),
    assignee: userRefSchema.nullable(),
    sla: slaDtoSchema,
    firstDetectedAt: iso,
    lastSeenAt: iso,
    occurrenceCount: z.number().int().min(0),
    reopenCount: z.number().int().min(0),
    pendingDecision: pendingDecisionSchema.nullable(),
    advisoryHint: advisoryHintSchema.nullable(),
    rev,
  })
  .strict();

/** The `AiAdvisoryCard` data (SPEC 9.3.6). Advisory only: it is never a status. */
export const advisoryDtoSchema = z
  .object({
    status: z.enum(/** @type {[string, ...string[]]} */ ([...ADVISORY_DTO_STATUSES])),
    suggestion: suggestion.optional(),
    confidence: z.number().int().min(0).max(100).optional(),
    confidenceBand: z.enum(["low", "medium", "high"]).optional(),
    reasoning: z.string().max(L.reasoningMax).optional(),
    provider: z.string().max(40).optional(),
    model: z.string().max(100).optional(),
    egressLevel: z
      .enum(/** @type {[string, ...string[]]} */ ([...ADVISORY_EGRESS_LEVELS]))
      .optional(),
    generatedAt: iso.optional(),
    stale: z.boolean(),
  })
  .strict();

const allowedActionSchema = z
  .object({
    action: z.enum(/** @type {[string, ...string[]]} */ ([...FINDING_ACTION_IDS])),
    allowed: z.boolean(),
    disabledReason: z.string().max(200).optional(),
  })
  .strict();

const evidenceDtoSchema = z
  .object({
    kind: z.string().max(10),
    language: z.string().max(30).nullable(),
    nodeKind: z.string().max(30).nullable(),
    startLine: z.number().int().nullable(),
    endLine: z.number().int().nullable(),
    focusStart: z.number().int().nullable(),
    focusEnd: z.number().int().nullable(),
    snippet: z.string().max(L.snippetBytesMax).nullable(),
    truncated: z.boolean(),
    purged: z.boolean(),
  })
  .strict();

/** `GET /findings/{id}`: the list item plus the detail (SPEC 8.3). */
export const findingDetailSchema = findingListItemSchema
  .extend({
    fingerprint: z.string().regex(/^fp1:[0-9a-f]{64}$/),
    fix: z
      .object({ fixedVersions: z.array(z.string().max(100)).max(10) })
      .strict()
      .nullable(),
    advisories: z
      .array(z.object({ id: z.string().max(60), family: z.string().max(20) }).strict())
      .max(20),
    confidence: z.enum(/** @type {[string, ...string[]]} */ ([...FINDING_CONFIDENCES])),
    provenance: z
      .object({
        tools: z
          .array(z.object({ toolId: z.string().max(40), displayName: z.string().max(80) }).strict())
          .max(6),
      })
      .strict(),
    evidence: evidenceDtoSchema.nullable(),
    link: z
      .object({
        url: z.string().max(2000),
        provider: z.string().max(20),
        commitShort: z.string().max(12),
        path: z.string().max(L.pathMax).nullable(),
        startLine: z.number().int().nullable(),
        endLine: z.number().int().nullable(),
      })
      .strict()
      .nullable(),
    advisory: advisoryDtoSchema,
    review: z
      .object({
        current: z
          .object({
            id: uuid,
            decision: z.enum(/** @type {[string, ...string[]]} */ ([...REVIEW_DECISIONS])),
            rationale: z.string().max(L.rationaleMax),
            reviewer: userRefSchema,
            severityOverride: sev.nullable(),
            submittedAt: iso,
          })
          .strict()
          .nullable(),
      })
      .strict(),
    exception: z
      .object({
        id: uuid,
        kind: z.enum(/** @type {[string, ...string[]]} */ ([...EXCEPTION_KINDS])),
        state: z.enum(/** @type {[string, ...string[]]} */ ([...EXCEPTION_STATES])),
        justification: z.string().max(L.justificationMax),
        expiresAt: iso.nullable(),
        requestedBy: userRefSchema,
        approvedBy: userRefSchema.nullable(),
      })
      .strict()
      .nullable(),
    remediation: z
      .object({
        assignment: z
          .object({
            id: uuid,
            assignee: userRefSchema,
            assignedBy: userRefSchema,
            assignedAt: iso,
            note: z.string().max(L.assignmentNoteMax).nullable(),
          })
          .strict()
          .nullable(),
        lastRecord: z
          .object({
            kind: z.enum(["work_started", "fix_submitted"]),
            at: iso,
            pullRequestUrl: z.string().max(L.pullRequestUrlMax).nullable(),
            ticketKey: z.string().max(20).nullable(),
            note: z.string().max(L.remediationNoteMax).nullable(),
          })
          .strict()
          .nullable(),
      })
      .strict(),
    lifecycle: z.object({ allowedActions: z.array(allowedActionSchema).max(40) }).strict(),
    coverage: z.object({ lastSeenAt: iso, notScannedRecently: z.boolean() }).strict(),
    similarCount: z.number().int().min(0),
  })
  .strict();

/** One entry of the merged timeline (`GET /findings/{id}/history`). */
export const historyEntrySchema = z
  .object({
    id: uuid,
    type: z.enum([
      "status",
      "review",
      "approval",
      "assignment",
      "remediation",
      "verification",
      "exception",
      "recurrence",
    ]),
    at: iso,
    actor: z.union([
      userRefSchema,
      z.object({ system: z.enum(["ingestion", "sla", "expiry"]) }).strict(),
    ]),
    fromStatus: status.nullable().optional(),
    toStatus: status.optional(),
    reason: z.string().max(60).optional(),
    note: z.string().max(L.historyNoteMax).nullable().optional(),
    detail: z
      .record(z.string().max(40), z.union([z.string().max(500), z.number(), z.boolean(), z.null()]))
      .optional(),
  })
  .strict();

export const commentDtoSchema = z
  .object({ id: uuid, author: userRefSchema, body: z.string().max(L.commentMax), createdAt: iso })
  .strict();

export const similarFindingSchema = z
  .object({
    id: uuid,
    title: z.string().max(L.titleMax),
    severity: sev,
    status,
    pipeline: z.object({ id: uuid, name: z.string().max(200) }).strict(),
  })
  .strict();

export const summaryDtoSchema = z
  .object({
    views: z
      .object({
        allOpen: z.number().int(),
        needsReview: z.number().int(),
        assignedToMe: z.number().int(),
        breachedSla: z.number().int(),
      })
      .strict(),
    bySeverity: z.record(sev, z.number().int()),
    byStatus: z.record(status, z.number().int()),
    pendingApprovals: z.number().int(),
    awaitingVerification: z.number().int(),
  })
  .strict();

/** A row of `GET /approvals`: the decision request, with `canDecide` computed by the server (SOD, permission). */
export const approvalQueueItemSchema = z
  .object({
    kind: z.enum(["review", "exception"]),
    requestId: uuid,
    finding: findingListItemSchema,
    requestedBy: userRefSchema,
    submittedAt: iso,
    decision: z.string().max(40).optional(),
    exceptionKind: z.enum(/** @type {[string, ...string[]]} */ ([...EXCEPTION_KINDS])).optional(),
    expiresAt: iso.nullable().optional(),
    rationalePreview: z.string().max(200),
    canDecide: z.boolean(),
    cannotDecideReason: z.enum(["separation_of_duties", "missing_permission"]).nullable(),
  })
  .strict();

export const boardColumnSchema = z
  .object({
    count: z.number().int().min(0),
    items: z
      .array(findingListItemSchema.extend({ canRemediate: z.boolean() }).strict())
      .max(L.boardFirstItems),
    nextCursor: z.string().nullable(),
  })
  .strict();
export const boardDtoSchema = z
  .object({
    columns: z.record(
      z.enum(/** @type {[string, ...string[]]} */ ([...BOARD_COLUMNS])),
      boardColumnSchema,
    ),
  })
  .strict();

export const slaSettingsDtoSchema = z
  .object({
    targets: z
      .array(
        z
          .object({ severity: sev, hours: z.number().int().nullable(), isDefault: z.boolean() })
          .strict(),
      )
      .length(5),
  })
  .strict();

export const bulkResultSchema = z
  .object({
    results: z
      .array(
        z
          .object({
            findingId: uuid,
            ok: z.boolean(),
            errorCode: z.string().max(60).optional(),
            reason: z.string().max(60).optional(),
          })
          .strict(),
      )
      .max(L.bulkMax),
  })
  .strict();
