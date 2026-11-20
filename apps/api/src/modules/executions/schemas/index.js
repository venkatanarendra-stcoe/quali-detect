import { z } from "zod";
import { createSuccessSchema } from "@qmentisai/contracts";
import { MAX_LIST_OFFSET } from "@qmentisai/db";
import {
  EXECUTION_STATUS_VALUES,
  coverageDtoSchema,
  toolRunDtoSchema,
  PIPELINE_TRIGGER_TYPES,
  SCAN_TASK_STATUS_VALUES,
} from "@qmentisai/shared";
import { uuidParams } from "../../../lib/http.js";
import { MAX_CURSOR_LENGTH } from "../../../lib/keyset.js";
import { sortSchema } from "../../../lib/query.js";
import {
  DEFAULT_LIST_LIMIT,
  DEFAULT_LOG_LIMIT,
  LIST_LIMITS,
  LOG_LEVELS,
  LOG_ORDERS,
  MAX_EVENTS_LIMIT,
  MAX_LOG_LIMIT,
  MAX_RANGE_DAYS,
  SORTABLE_FIELDS,
} from "../constants/index.js";

/**
 * Zod contracts of the executions HTTP API (SPEC executions §8): strict params, query, body and header schemas (unknown keys
 * are 400, so `page`, `tenantId`, `workspaceId` and `mode` are all refused) and the response schemas the OpenAPI document is
 * generated from. Nothing here accepts an identifier of a tenant.
 */

export const executionParamsSchema = uuidParams("executionId");

const cursor = z.string().min(1).max(MAX_CURSOR_LENGTH);
const isoInstant = z
  .string()
  .regex(
    /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{1,6})?(Z|[+-]\d{2}:\d{2})$/,
    "Use an ISO 8601 instant with a zone, for example 2026-11-16T10:00:00Z.",
  )
  .transform((value, ctx) => {
    const date = new Date(value);
    if (Number.isNaN(date.getTime())) {
      ctx.addIssue({ code: z.ZodIssueCode.custom, message: "This is not a valid instant." });
      return z.NEVER;
    }
    return date;
  });

/** `status=failed&status=partial` or `status=failed,partial`: a de-duplicated, sorted list (stable for the cursor binding). */
const statusList = z
  .union([z.string().max(200), z.array(z.string().max(40)).max(11)])
  .transform((value, ctx) => {
    const raw = (Array.isArray(value) ? value : [value]).flatMap((v) => v.split(","));
    const out = new Set();
    for (const part of raw) {
      if (!EXECUTION_STATUS_VALUES.includes(part)) {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          message: `status must be one or more of ${EXECUTION_STATUS_VALUES.join(", ")}.`,
        });
        return z.NEVER;
      }
      out.add(part);
    }
    return [...out].sort();
  });

const DAY_MS = 86400000;
export const listQuerySchema = z
  .object({
    workspaceId: z.string().uuid().optional(),
    pipelineId: z.string().uuid().optional(),
    repositoryId: z.string().uuid().optional(),
    status: statusList.optional(),
    triggerType: z.enum(PIPELINE_TRIGGER_TYPES).optional(),
    from: isoInstant.optional(),
    to: isoInstant.optional(),
    sort: sortSchema(SORTABLE_FIELDS, [{ field: "requestedAt", direction: "desc" }]),
    cursor: cursor.optional(),
    page: z.coerce.number().int().min(1).optional(),
    limit: z.coerce
      .number()
      .int()
      .refine((n) => LIST_LIMITS.includes(n), `limit must be one of ${LIST_LIMITS.join(", ")}.`)
      .default(DEFAULT_LIST_LIMIT),
  })
  .strict()
  .superRefine((q, ctx) => {
    if (q.page !== undefined && q.cursor !== undefined)
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        path: ["page"],
        message: "page cannot be combined with cursor.",
      });
    else if (q.page !== undefined && q.page * q.limit > MAX_LIST_OFFSET)
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        path: ["page"],
        message: `page * limit is at most ${MAX_LIST_OFFSET}; narrow the filters to reach older executions.`,
      });
    if (q.from && q.to) {
      if (q.to.getTime() <= q.from.getTime())
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          path: ["to"],
          message: "to must be after from.",
        });
      else if (q.to.getTime() - q.from.getTime() > MAX_RANGE_DAYS * DAY_MS)
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          path: ["to"],
          message: `The range from..to is at most ${MAX_RANGE_DAYS} days.`,
        });
    }
  });

export const eventsQuerySchema = z
  .object({
    cursor: cursor.optional(),
    limit: z.coerce.number().int().min(1).max(MAX_EVENTS_LIMIT).default(50),
  })
  .strict();

export const logsQuerySchema = z
  .object({
    order: z.enum(LOG_ORDERS).default("asc"),
    afterSeq: z.coerce.number().int().min(0).max(2147483647).optional(),
    cursor: cursor.optional(),
    taskId: z.string().uuid().optional(),
    level: z.enum(LOG_LEVELS).optional(),
    limit: z.coerce.number().int().min(1).max(MAX_LOG_LIMIT).default(DEFAULT_LOG_LIMIT),
  })
  .strict()
  .superRefine((q, ctx) => {
    if (q.cursor !== undefined && q.afterSeq !== undefined)
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        path: ["afterSeq"],
        message: "afterSeq cannot be combined with cursor.",
      });
    if (q.order === "desc" && q.afterSeq !== undefined)
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        path: ["afterSeq"],
        message: "afterSeq needs order=asc; page the tail with the cursor.",
      });
  });

/** Cancel takes no body; a `mode` (or any other) field is refused (ER-19). An absent body is accepted. */
export const cancelBodySchema = z.object({}).strict().optional();
export const retryBodySchema = z.object({}).strict().optional();
/** Retry REQUIRES the key (ER-23). The route kit's idempotency middleware validates the same pattern and scopes it. */
export const retryHeadersSchema = z
  .object({ "idempotency-key": z.string().regex(/^[A-Za-z0-9._:-]{8,128}$/) })
  .passthrough();

const iso = z.string();
const nullableIso = z.string().nullable();
const severityCounts = z.record(z.number());

const taskSummary = z.object({
  total: z.number(),
  succeeded: z.number(),
  failed: z.number(),
  running: z.number(),
});
/**
 * A stable lower-case machine code (the UI maps it to text). `succeeded` carries exactly one: `no_applicable_scans` (the scan
 * decision selected no scan; nothing started and the quota unit was given back). Every other status that ends a run carries its
 * own reason (cancelled, failed, partial, timed_out, blocked, skipped); `queued`, `preparing` and `running` carry none.
 */
const statusReason = z
  .string()
  .nullable()
  .describe(
    "Stable machine code. A succeeded execution carries only no_applicable_scans (the scan decision selected no scan; the quota unit was given back).",
  );
const base = {
  id: z.string(),
  workspaceId: z.string(),
  pipeline: z.object({ id: z.string(), name: z.string().optional() }),
  repository: z.object({ id: z.string(), fullName: z.string() }).nullable(),
  status: z.string(),
  statusReason,
  triggerType: z.string(),
  triggerKey: z.string(),
  refType: z.string(),
  refName: z.string(),
  pullRequestNumber: z.number().nullable(),
  commitSha: z.string().nullable(),
  scanKind: z.string(),
  scanKindReason: z.string(),
  trust: z.string(),
  requestedAt: iso,
  startedAt: nullableIso,
  finishedAt: nullableIso,
  durationMs: z.number().nullable(),
  taskSummary,
  cancelRequested: z.boolean(),
  retryOfExecutionId: z.string().nullable(),
};
const listItem = z.object(base);
const task = z.object({
  id: z.string(),
  scanType: z.string(),
  status: z.enum(SCAN_TASK_STATUS_VALUES),
  statusReason: z.string().nullable(),
  attempt: z.number(),
  maxAttempts: z.number(),
  engine: z.object({ id: z.string(), profile: z.string() }),
  startedAt: nullableIso,
  finishedAt: nullableIso,
  resultSummary: z
    .object({
      itemCount: z.number(),
      severityCounts,
      truncated: z.boolean(),
      completeness: z.string(),
    })
    .nullable(),
  tools: z
    .array(toolRunDtoSchema)
    .optional()
    .describe(
      "Tool runs of the latest attempt (ensemble engines only; omitted for older executions and unfinished tasks).",
    ),
  coverage: coverageDtoSchema
    .optional()
    .describe("Coverage statement of the result (ensemble engines only)."),
});
const decisionScanType = z.object({
  scanType: z.string(),
  state: z.enum(["required", "added", "not_selected", "not_enabled"]),
  ruleIds: z.array(z.string()),
  reason: z.string().nullable(),
  taskId: z.string().nullable(),
});
/** The scan decision of an execution (docs/modules/scan-decisioning/SPEC.md 8); `null` for an execution without a record. */
const decision = z
  .object({
    scanKind: z.string(),
    diff: z.object({
      source: z.string(),
      status: z.string(),
      changedTotal: z.number(),
      summary: z.object({
        byClass: z.record(z.number()),
        byStatus: z.record(z.number()),
        additions: z.number(),
        deletions: z.number(),
        samples: z.record(z.array(z.string())),
      }),
    }),
    secretsRule: z.string(),
    scanTypes: z.array(decisionScanType),
    agent: z.object({
      status: z.string(),
      provider: z.string().nullable(),
      model: z.string().nullable(),
      summary: z.string().nullable(),
      usage: z
        .object({ inputTokens: z.number(), outputTokens: z.number(), latencyMs: z.number() })
        .nullable(),
    }),
    decidedAt: z.string(),
  })
  .nullable();
const detail = z.object({
  ...base,
  configVersion: z.number(),
  configHash: z.string(),
  requestedBy: z.object({ id: z.string(), displayName: z.string() }).nullable(),
  baseRef: z.string().nullable(),
  deadlineAt: nullableIso,
  cancelRequestedAt: nullableIso,
  cancelMode: z.string().nullable(),
  tasks: z.array(task),
  resolutionEligible: z.boolean(),
  decision,
  rev: z.number(),
});
const event = z.object({
  seq: z.number(),
  at: iso,
  type: z.string(),
  fromStatus: z.string().nullable(),
  toStatus: z.string().nullable(),
  reason: z.string().nullable(),
  actorType: z.string(),
});
const logLine = z.object({
  seq: z.number(),
  at: iso,
  level: z.string(),
  source: z.string(),
  taskId: z.string().nullable(),
  message: z.string(),
});
const action = z.object({
  id: z.string(),
  workspaceId: z.string(),
  pipelineId: z.string(),
  status: z.string(),
  statusReason: z.string().nullable(),
  triggerType: z.string(),
  refType: z.string(),
  refName: z.string(),
  pullRequestNumber: z.number().nullable(),
  commitSha: z.string().nullable(),
  scanKind: z.string(),
  scanKindReason: z.string(),
  trust: z.string(),
  requestedAt: iso,
  retryOfExecutionId: z.string().nullable(),
  cancelRequested: z.boolean(),
  cancelRequestedAt: nullableIso,
  cancelMode: z.string().nullable(),
});

/**
 * Pagination block of the list: the cursor fields always; the numbered-page fields (`page`, `pageSize`, `totalItems`,
 * `totalPages`) only when the request used `page` (the count is not run for cursor requests, SPEC CF-10 amended).
 */
const listPagination = z.object({
  limit: z.number().int().min(1),
  nextCursor: z.string().nullable(),
  hasMore: z.boolean(),
  page: z.number().int().min(1).optional(),
  pageSize: z.number().int().min(1).optional(),
  totalItems: z.number().int().min(0).optional(),
  totalPages: z.number().int().min(0).optional(),
});
const cursorOnlyEnvelope = (item) =>
  z.object({
    success: z.literal(true),
    data: z.array(item),
    meta: z.object({
      correlationId: z.string(),
      pagination: z.object({
        limit: z.number().int().min(1),
        nextCursor: z.string().nullable(),
        hasMore: z.boolean(),
      }),
    }),
  });

export const responses = Object.freeze({
  list: z.object({
    success: z.literal(true),
    data: z.array(listItem),
    meta: z.object({ correlationId: z.string(), pagination: listPagination }),
  }),
  detail: createSuccessSchema(detail),
  events: cursorOnlyEnvelope(event),
  logs: createSuccessSchema(
    z.object({
      lines: z.array(logLine),
      nextCursor: z.string().nullable(),
      hasMore: z.boolean(),
      truncated: z.boolean(),
    }),
  ),
  cancelled: createSuccessSchema(z.object({ execution: action })),
  cancelRequested: createSuccessSchema(
    z.object({ execution: action, cancelRequested: z.literal(true) }),
  ),
  retried: createSuccessSchema(z.object({ execution: action })),
});
