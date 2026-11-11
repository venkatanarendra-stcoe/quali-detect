import { z } from "zod";
import { createPaginatedSchema, createSuccessSchema } from "@qmentisai/contracts";
import { searchText, text, uuidParams } from "../../../lib/http.js";
import { createCollectionQuerySchema } from "../../../lib/query.js";
import { LISTED_STATUSES, SORTABLE_FIELDS } from "../constants/index.js";

export const userParamsSchema = uuidParams("userId");
export const listUsersQuerySchema = createCollectionQuerySchema({
  sortableFields: SORTABLE_FIELDS,
  defaultSort: [{ field: "name", direction: "asc" }],
  filters: { status: z.enum(LISTED_STATUSES).optional(), q: searchText },
});
export const inviteUserBodySchema = z
  .object({ email: z.string().trim().toLowerCase().email().max(254), name: text(120) })
  .strict();
export const updateUserBodySchema = z.object({ status: z.enum(["active", "suspended"]) }).strict();
export const effectivePermissionsQuerySchema = z
  .object({ workspaceId: z.string().uuid().optional() })
  .strict();

const userDto = z.object({
  userId: z.string(),
  email: z.string(),
  name: z.string().nullable(),
  status: z.string(),
  joinedAt: z.string().nullable(),
  invitedAt: z.string(),
  lastLoginAt: z.string().nullable(),
});
export const userResponseSchema = createSuccessSchema(userDto);
export const userListResponseSchema = createPaginatedSchema(userDto);
export const removedResponseSchema = createSuccessSchema(z.object({ removed: z.literal(true) }));
export const effectivePermissionsResponseSchema = createSuccessSchema(
  z.object({
    permissions: z.object({
      tenant: z.array(z.string()),
      allWorkspaces: z.array(z.string()),
      workspaces: z.array(
        z.object({
          id: z.string(),
          name: z.string(),
          status: z.string(),
          permissions: z.array(z.string()),
        }),
      ),
    }),
    assignments: z.array(
      z.object({
        id: z.string(),
        roleId: z.string(),
        roleName: z.string(),
        via: z.enum(["user", "group"]),
        scopeType: z.enum(["tenant", "workspace"]),
        workspaceId: z.string().nullable(),
        expiresAt: z.string().nullable(),
      }),
    ),
  }),
);
