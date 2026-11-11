import { z } from "zod";
import { createPaginatedSchema, createSuccessSchema } from "@qmentisai/contracts";
import { uuidParams } from "../../../lib/http.js";

export const linkParamsSchema = uuidParams("linkId");
export const startBodySchema = z.object({}).strict().optional();
export const authorizeBodySchema = z
  .object({ installationId: z.string().regex(/^\d{1,20}$/, "An installation id is digits only.") })
  .strict();
export const linkBodySchema = z
  .object({ code: z.string().min(1).max(200), state: z.string().min(20).max(100) })
  .strict();
export const scopeBodySchema = z
  .object({ workspaceIds: z.array(z.string().uuid()).max(500) })
  .strict();
export const unlinkBodySchema = z.object({ confirm: z.string().min(1).max(200) }).strict();
export const deliveriesQuerySchema = z
  .object({
    page: z.coerce.number().int().min(1).default(1),
    pageSize: z.coerce.number().int().min(1).max(100).default(25),
  })
  .strict();

const linkDto = z.object({
  id: z.string(),
  provider: z.literal("github"),
  status: z.enum(["linked", "unlinked"]),
  health: z.enum(["healthy", "degraded", "suspended", "revoked", "unlinked"]),
  account: z.object({ login: z.string(), type: z.enum(["organization", "user"]) }),
  externalInstallationId: z.string(),
  repositorySelection: z.enum(["all", "selected"]),
  permissions: z.record(z.unknown()),
  linkedAt: z.string(),
  linkedByUserId: z.string(),
  repositoryCount: z.number(),
  unavailableRepositoryCount: z.number(),
  workspaceScope: z.array(z.string()),
});
const catalogItem = z.object({
  provider: z.string(),
  name: z.string(),
  category: z.string(),
  available: z.boolean(),
  beta: z.boolean().optional(),
  status: z.enum(["connected", "degraded", "not_connected", "not_available", "not_configured"]),
});
export const catalogResponseSchema = createSuccessSchema(z.object({ items: z.array(catalogItem) }));
export const githubOverviewResponseSchema = createSuccessSchema(
  z.object({ configured: z.boolean(), status: z.string(), installations: z.number() }),
);
export const startResponseSchema = createSuccessSchema(z.object({ installUrl: z.string() }));
export const authorizeResponseSchema = createSuccessSchema(z.object({ authorizeUrl: z.string() }));
export const linkResponseSchema = createSuccessSchema(linkDto);
export const linkListResponseSchema = createSuccessSchema(z.object({ items: z.array(linkDto) }));
export const unlinkResponseSchema = createSuccessSchema(
  z.object({ unlinked: z.literal(true), repositoriesDisconnected: z.number() }),
);
const deliveryDto = z.object({
  id: z.string(),
  receivedAt: z.string(),
  event: z.string(),
  action: z.string().nullable(),
  outcome: z.string(),
  signatureVerified: z.literal(true),
});
export const deliveryListResponseSchema = createPaginatedSchema(deliveryDto);
