import { z } from "zod";
import { createCursorPaginatedSchema, createSuccessSchema } from "@qmentisai/contracts";
import { searchText, text, uuidParams } from "../../../lib/http.js";
import { createCollectionQuerySchema } from "../../../lib/query.js";
import { LIFECYCLE_ACTIONS, SORTABLE_FIELDS, TENANT_STATUSES } from "../constants/index.js";

export const tenantParamsSchema = uuidParams("tenantId");

export const listTenantsQuerySchema = createCollectionQuerySchema({
  cursor: true,
  sortableFields: SORTABLE_FIELDS,
  defaultSort: [{ field: "name", direction: "asc" }],
  filters: {
    status: z.enum(TENANT_STATUSES).optional(),
    plan: z.string().trim().min(1).max(60).optional(),
    q: searchText,
  },
});

/** Slug: lowercase letters, digits and inner hyphens, 3-40 characters. */
export const slugSchema = z
  .string()
  .trim()
  .toLowerCase()
  .regex(
    /^[a-z0-9][a-z0-9-]{1,38}[a-z0-9]$/,
    "Use 3-40 lowercase letters, digits or hyphens (no leading or trailing hyphen).",
  );

export const provisionTenantBodySchema = z
  .object({
    name: text(120),
    slug: slugSchema,
    status: z.enum(["trial", "active"]).default("trial"),
    planVersionId: z.string().uuid().optional(),
    admin: z
      .object({ email: z.string().trim().toLowerCase().email().max(254), name: text(120) })
      .strict(),
  })
  .strict();

export const lifecycleBodySchema = z
  .object({
    reason: text(500).min(5, "Give a reason of at least 5 characters."),
    confirm: z.string().max(200).optional(),
  })
  .strict();

const planDto = z.object({ key: z.string(), name: z.string(), version: z.number() });
const tenantItemDto = z.object({
  id: z.string(),
  slug: z.string(),
  name: z.string(),
  status: z.enum(TENANT_STATUSES),
  plan: planDto.nullable(),
  userCount: z.number(),
  workspaceCount: z.number(),
  createdAt: z.string(),
});
export const tenantListResponseSchema = createCursorPaginatedSchema(tenantItemDto);

const tenantDetailDto = z.object({
  tenant: z.object({
    id: z.string(),
    slug: z.string(),
    name: z.string(),
    status: z.enum(TENANT_STATUSES),
    createdAt: z.string(),
    deactivatedAt: z.string().nullable(),
    /** Until when a Super Admin can restore a deactivated tenant; null when not deactivated or the window ended. */
    restorableUntil: z.string().nullable(),
  }),
  subscription: z
    .object({
      status: z.string(),
      startsAt: z.string(),
      endsAt: z.string().nullable(),
      plan: planDto,
    })
    .nullable(),
  usage: z.object({
    users: z.object({ active: z.number(), invited: z.number(), suspended: z.number() }),
    workspaces: z.object({ active: z.number(), archived: z.number() }),
    groups: z.number(),
  }),
  administrators: z.array(z.object({ id: z.string(), name: z.string(), email: z.string() })),
  pendingAdministrators: z.array(z.object({ id: z.string(), email: z.string() })),
  lifecycle: z
    .array(
      z.object({
        action: z.string(),
        at: z.string(),
        actorName: z.string().nullable(),
        reason: z.string().nullable(),
      }),
    )
    .nullable(),
  allowedActions: z.array(z.enum(LIFECYCLE_ACTIONS)),
});
export const tenantDetailResponseSchema = createSuccessSchema(tenantDetailDto);

export const planVersionsResponseSchema = createSuccessSchema(
  z.array(
    z.object({
      planVersionId: z.string(),
      planKey: z.string(),
      planName: z.string(),
      version: z.number(),
    }),
  ),
);
