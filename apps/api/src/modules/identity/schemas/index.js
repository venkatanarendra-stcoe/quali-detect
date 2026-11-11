import { z } from "zod";
import { createSuccessSchema } from "@qmentisai/contracts";

export const loginBodySchema = z
  .object({
    email: z.string().trim().toLowerCase().email().max(254),
    password: z.string().min(1).max(256),
  })
  .strict();

export const switchTenantBodySchema = z.object({ tenantId: z.string().uuid() }).strict();
export const tenantIdParamsSchema = z.object({ tenantId: z.string().uuid() }).strict();
export const permissionsQuerySchema = z
  .object({ workspaceId: z.string().uuid().optional() })
  .strict();

const userDto = z.object({
  id: z.string(),
  email: z.string(),
  name: z.string(),
  status: z.string(),
});
const tenantDto = z.object({
  id: z.string(),
  slug: z.string(),
  name: z.string(),
  status: z.string(),
});
export const permissionSetDto = z.object({
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
});

export const loginResponseSchema = createSuccessSchema(
  z.object({
    user: userDto,
    tenant: tenantDto.nullable(),
    tenants: z.array(tenantDto),
    requiresTenantSelection: z.boolean(),
  }),
);
export const logoutResponseSchema = createSuccessSchema(z.object({ loggedOut: z.literal(true) }));
export const meResponseSchema = createSuccessSchema(
  z.object({
    user: userDto,
    tenant: tenantDto.nullable(),
    membership: z.object({ status: z.string(), joinedAt: z.string().nullable() }).nullable(),
    permissions: permissionSetDto,
    session: z.object({ expiresAt: z.string(), authMethod: z.string(), mfaVerified: z.boolean() }),
  }),
);
export const tenantsResponseSchema = createSuccessSchema(z.array(tenantDto));
export const switchTenantResponseSchema = createSuccessSchema(z.object({ tenant: tenantDto }));
export const myPermissionsResponseSchema = createSuccessSchema(permissionSetDto);
export const invitationsResponseSchema = createSuccessSchema(z.array(tenantDto));
export const acceptInvitationResponseSchema = createSuccessSchema(z.object({ tenant: tenantDto }));
