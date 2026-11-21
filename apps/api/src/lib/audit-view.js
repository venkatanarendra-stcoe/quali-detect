import { z } from "zod";
import { createCursorPaginatedSchema, createPaginatedSchema } from "@qmentisai/contracts";
import { createCollectionQuerySchema } from "./query.js";

/** Sort fields of both audit-log read APIs as keyset terms (createdAt, action; `id` breaks ties). */
export const AUDIT_KEY_SPECS = Object.freeze({
  createdAt: { type: "date", column: "created_at" },
  action: { type: "string" },
});

/**
 * Shared pieces of the two audit-log read APIs (tenant and platform).
 *
 * The audit tables have no result column: every row is a recorded event. The API exposes a DERIVED `result`:
 * "failure" for the security events that record a refusal (`*_failed`, `*_denied`, `*throttle_cap_reached`),
 * "success" for everything else. (Open: a stored result column if refusals start being audited more widely.)
 */
const FAILURE_SUFFIXES = Object.freeze(["_failed", "_denied", "throttle_cap_reached"]);

/** @param {string} action @returns {"success" | "failure"} */
export const resultOf = (action) =>
  FAILURE_SUFFIXES.some((suffix) => action.endsWith(suffix)) ? "failure" : "success";

/** Prisma `where` fragment for the `result` filter. @param {"success" | "failure" | undefined} result */
export function resultWhere(result) {
  if (!result) return {};
  const failing = FAILURE_SUFFIXES.map((suffix) => ({ action: { endsWith: suffix } }));
  return result === "failure" ? { OR: failing } : { NOT: { OR: failing } };
}

/** Prisma `where` fragment for the date range. @param {Date | undefined} from @param {Date | undefined} to */
export const rangeWhere = (from, to) =>
  from || to ? { createdAt: { ...(from ? { gte: from } : {}), ...(to ? { lte: to } : {}) } } : {};

const isoDate = z
  .string()
  .datetime({ offset: true })
  .transform((value) => new Date(value));

/**
 * Query schema: pagination, `sort` (createdAt, action), and the filters actor, action, from, to, result.
 * @param {Record<string, import("zod").ZodTypeAny>} [extraFilters]
 * @param {{ cursor?: boolean }} [options] `cursor: true` adds the cursor pagination parameters (tenant audit log only)
 */
export function auditQuerySchema(extraFilters = {}, { cursor = false } = {}) {
  return createCollectionQuerySchema({
    cursor,
    sortableFields: ["createdAt", "action"],
    defaultSort: [{ field: "createdAt", direction: "desc" }],
    pagination: { defaultPageSize: 25, maxPageSize: 100 },
    filters: {
      actor: z.string().uuid().optional(),
      action: z
        .string()
        .max(100)
        .regex(/^[a-z_]+(\.[a-z_]+)+$/, "Use an audit action such as role.created.")
        .optional(),
      from: isoDate.optional(),
      to: isoDate.optional(),
      result: z.enum(["success", "failure"]).optional(),
      ...extraFilters,
    },
  }).refine((q) => !q.from || !q.to || q.from <= q.to, {
    message: "from must not be after to.",
    path: ["from"],
  });
}

const actorDto = z
  .object({
    type: z.string(),
    id: z.string().nullable(),
    name: z.string().nullable(),
    email: z.string().nullable(),
  })
  .nullable();
export const auditEntryDto = z.object({
  id: z.string(),
  createdAt: z.string(),
  action: z.string(),
  result: z.enum(["success", "failure"]),
  actor: actorDto,
  target: z.object({ type: z.string().nullable(), id: z.string().nullable() }),
  workspaceId: z.string().nullable(),
  tenantId: z.string().nullable(),
  correlationId: z.string().nullable(),
  ipAddress: z.string().nullable(),
  changes: z.record(z.unknown()).nullable(),
  metadata: z.record(z.unknown()).nullable(),
});
export const auditListResponseSchema = createPaginatedSchema(auditEntryDto);
export const auditCursorListResponseSchema = createCursorPaginatedSchema(auditEntryDto);
