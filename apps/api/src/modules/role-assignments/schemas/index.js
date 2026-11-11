import { z } from "zod";
import { createPaginatedSchema, createSuccessSchema } from "@qmentisai/contracts";
import { atLeastOne, uuidParams } from "../../../lib/http.js";
import { createCollectionQuerySchema } from "../../../lib/query.js";
import { SORTABLE_FIELDS } from "../constants/index.js";

const futureDate = z
  .string()
  .datetime()
  .transform((value) => new Date(value));

export const assignmentParamsSchema = uuidParams("assignmentId");
export const workspaceParamsSchema = uuidParams("workspaceId");
export const workspaceAssignmentParamsSchema = uuidParams("workspaceId", "assignmentId");
export const listAssignmentsQuerySchema = createCollectionQuerySchema({
  sortableFields: SORTABLE_FIELDS,
  defaultSort: [{ field: "createdAt", direction: "desc" }],
  filters: {
    subjectType: z.enum(["user", "group"]).optional(),
    subjectId: z.string().uuid().optional(),
    roleId: z.string().uuid().optional(),
    status: z.enum(["active", "suspended"]).optional(),
  },
});
export const createAssignmentBodySchema = z
  .object({
    subjectType: z.enum(["user", "group"]),
    subjectId: z.string().uuid(),
    roleId: z.string().uuid(),
    expiresAt: futureDate.nullish(),
  })
  .strict();
export const updateAssignmentBodySchema = atLeastOne(
  z.object({
    status: z.enum(["active", "suspended"]).optional(),
    expiresAt: futureDate.nullable().optional(),
  }),
);

const assignmentDto = z.object({
  id: z.string(),
  subjectType: z.enum(["user", "group"]),
  subject: z.object({ id: z.string(), name: z.string(), email: z.string().nullable() }),
  role: z.object({ id: z.string(), key: z.string(), name: z.string(), kind: z.string() }),
  scopeType: z.enum(["tenant", "workspace"]),
  workspaceId: z.string().nullable(),
  status: z.enum(["active", "suspended"]),
  expiresAt: z.string().nullable(),
  createdByUserId: z.string().nullable(),
  createdAt: z.string(),
});
export const assignmentResponseSchema = createSuccessSchema(assignmentDto);
export const assignmentListResponseSchema = createPaginatedSchema(assignmentDto);
export const revokedResponseSchema = createSuccessSchema(z.object({ revoked: z.literal(true) }));
