import { z } from "zod";
import { createPaginatedSchema, createSuccessSchema } from "@qmentisai/contracts";
import { atLeastOne, searchText, text, uuidParams } from "../../../lib/http.js";
import { createCollectionQuerySchema } from "../../../lib/query.js";
import { SORTABLE_FIELDS } from "../constants/index.js";

export const workspaceParamsSchema = uuidParams("workspaceId");

export const listWorkspacesQuerySchema = createCollectionQuerySchema({
  sortableFields: SORTABLE_FIELDS,
  defaultSort: [{ field: "name", direction: "asc" }],
  filters: { status: z.enum(["active", "archived"]).optional(), q: searchText },
});

/** `GET /overview`: no parameters (a client-supplied tenant or workspace id is a 400, never ignored). */
export const overviewQuerySchema = z.object({}).strict();
export const overviewResponseSchema = createSuccessSchema(
  z.object({ accessibleWorkspaces: z.number().int().nonnegative() }),
);

export const createWorkspaceBodySchema = z
  .object({
    name: text(120),
    description: text(1000).nullish(),
    businessUnit: text(120).nullish(),
    ownerUserId: z.string().uuid().optional(),
  })
  .strict();

export const updateWorkspaceBodySchema = atLeastOne(
  z.object({
    name: text(120).optional(),
    description: text(1000).nullable().optional(),
    businessUnit: text(120).nullable().optional(),
    ownerUserId: z.string().uuid().nullable().optional(),
  }),
);

export const workspaceDtoSchema = z.object({
  id: z.string(),
  name: z.string(),
  description: z.string().nullable(),
  businessUnit: z.string().nullable(),
  ownerUserId: z.string().nullable(),
  ownerName: z.string().nullable(),
  memberCount: z.number(),
  status: z.enum(["active", "archived"]),
  archivedAt: z.string().nullable(),
  createdAt: z.string(),
  updatedAt: z.string(),
});
export const workspaceResponseSchema = createSuccessSchema(workspaceDtoSchema);
export const workspaceListResponseSchema = createPaginatedSchema(workspaceDtoSchema);
