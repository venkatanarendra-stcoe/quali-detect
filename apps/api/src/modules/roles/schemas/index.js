import { z } from "zod";
import { createPaginatedSchema, createSuccessSchema } from "@qmentisai/contracts";
import { atLeastOne, searchText, text, uuidParams } from "../../../lib/http.js";
import { createCollectionQuerySchema } from "../../../lib/query.js";
import { SORTABLE_FIELDS } from "../constants/index.js";

const permissionKeys = z.array(z.string().trim().min(1).max(100)).max(200);

export const roleParamsSchema = uuidParams("roleId");
export const listRolesQuerySchema = createCollectionQuerySchema({
  sortableFields: SORTABLE_FIELDS,
  defaultSort: [{ field: "name", direction: "asc" }],
  filters: { kind: z.enum(["built_in", "custom"]).optional(), q: searchText },
});
/** `permissions` are flat catalog keys (tenant and workspace scope); `cloneFromRoleId` copies a visible role's keys. */
export const createRoleBodySchema = z
  .object({
    name: text(80),
    description: text(500),
    permissions: permissionKeys.optional(),
    cloneFromRoleId: z.string().uuid().optional(),
  })
  .strict();
export const updateRoleBodySchema = atLeastOne(
  z.object({
    name: text(80).optional(),
    description: text(500).optional(),
    permissions: permissionKeys.optional(),
  }),
);

const roleDto = z.object({
  id: z.string(),
  key: z.string(),
  name: z.string(),
  description: z.string().nullable(),
  kind: z.enum(["built_in", "custom"]),
  tenantPermissions: z.array(z.string()),
  workspacePermissions: z.array(z.string()),
  assignmentCount: z.number(),
  createdAt: z.string(),
  updatedAt: z.string(),
});
export const roleResponseSchema = createSuccessSchema(roleDto);
export const roleListResponseSchema = createPaginatedSchema(roleDto);
export const deletedResponseSchema = createSuccessSchema(z.object({ deleted: z.literal(true) }));
export const permissionCatalogResponseSchema = createSuccessSchema(
  z.array(
    z.object({ key: z.string(), scope: z.enum(["tenant", "workspace"]), description: z.string() }),
  ),
);
