import { z } from "zod";
import { createPaginatedSchema, createSuccessSchema } from "@qmentisai/contracts";
import { uuidParams } from "../../../lib/http.js";
import { paginationShape } from "../../../lib/query.js";

export const linkParamsSchema = uuidParams("linkId");
export const workspaceParamsSchema = uuidParams("workspaceId");
export const workspaceLinkParamsSchema = uuidParams("workspaceId", "linkId");
export const authorizeBodySchema = z
  .object({ installationId: z.string().regex(/^\d{1,20}$/, "An installation id is digits only.") })
  .strict();
export const linkBodySchema = z
  .object({ code: z.string().min(1).max(200), state: z.string().min(20).max(100) })
  .strict();
export const unlinkBodySchema = z.object({ confirm: z.string().min(1).max(200) }).strict();
export const settingsBodySchema = z.object({ allowWorkspaceLinking: z.boolean() }).strict();
export const deliveriesQuerySchema = z
  .object({
    page: z.coerce.number().int().min(1).default(1),
    pageSize: z.coerce.number().int().min(1).max(100).default(25),
  })
  .strict();
export const allowListQuerySchema = z
  .object({
    ...paginationShape({ defaultPageSize: 30, maxPageSize: 100 }),
    q: z.string().trim().min(1).max(100).optional(),
  })
  .strict();
const repoId = z.string().regex(/^\d{1,19}$/);
/** Replace the whole list (`externalRepoIds`) or patch it (`add` / `remove`); never both. */
export const allowListBodySchema = z
  .object({
    externalRepoIds: z.array(repoId).max(500).optional(),
    add: z.array(repoId).max(500).optional(),
    remove: z.array(repoId).max(500).optional(),
  })
  .strict()
  .refine(
    (b) =>
      (b.externalRepoIds !== undefined && b.add === undefined && b.remove === undefined) ||
      (b.externalRepoIds === undefined && (b.add !== undefined || b.remove !== undefined)),
    { message: "Send either externalRepoIds (replace) or add/remove (patch)." },
  );

const linkStatus = z.enum(["linked", "unlinked", "revoked", "suspended"]);
/** Why a link reads revoked or suspended (SPEC §16.2); null while linked or unlinked. */
const statusReason = z.enum(["uninstalled", "suspended", "not_found_on_github"]).nullable();
const health = z.enum(["healthy", "degraded", "suspended", "revoked", "unlinked"]);
const account = z.object({ login: z.string(), type: z.enum(["organization", "user"]) });
const installationDto = z.object({
  id: z.string(),
  provider: z.literal("github"),
  status: linkStatus,
  statusChangedAt: z.string().nullable(),
  statusReason,
  health,
  account,
  externalInstallationId: z.string(),
  repositorySelection: z.enum(["all", "selected"]),
  permissions: z.record(z.unknown()),
  linkedAt: z.string(),
  linkedByUserId: z.string(),
  repositoryCount: z.number(),
  unavailableRepositoryCount: z.number(),
  workspaceCount: z.number(),
  workspaces: z.array(z.object({ id: z.string(), name: z.string() })),
  hiddenWorkspaceCount: z.number(),
});
const workspaceLinkDto = z.object({
  id: z.string(),
  workspaceId: z.string(),
  installationLinkId: z.string(),
  provider: z.literal("github"),
  status: linkStatus,
  statusChangedAt: z.string().nullable(),
  statusReason,
  health,
  account,
  repositorySelection: z.enum(["all", "selected"]),
  linkedAt: z.string(),
  linkedByUserId: z.string(),
  repositoryCount: z.number(),
  unavailableRepositoryCount: z.number(),
  allowListCount: z.number(),
  lastEventAt: z.string().nullable(),
});
const catalogItem = z.object({
  provider: z.string(),
  name: z.string(),
  category: z.string(),
  available: z.boolean(),
  beta: z.boolean().optional(),
  status: z.enum(["connected", "degraded", "not_connected", "not_available", "not_configured"]),
});
const deliveryDto = z.object({
  id: z.string(),
  receivedAt: z.string(),
  event: z.string(),
  action: z.string().nullable(),
  outcome: z.string(),
  signatureVerified: z.literal(true),
});
const allowListItem = z.object({
  externalRepoId: z.string(),
  fullName: z.string(),
  visibility: z.string(),
  defaultBranch: z.string().nullable(),
  archived: z.boolean(),
  allowed: z.boolean(),
  allowedElsewhere: z.boolean(),
  connected: z.boolean(),
});

export const catalogResponseSchema = createSuccessSchema(z.object({ items: z.array(catalogItem) }));
export const githubOverviewResponseSchema = createSuccessSchema(
  z.object({
    configured: z.boolean(),
    status: z.string(),
    installations: z.number(),
    allowWorkspaceLinking: z.boolean(),
  }),
);
export const startResponseSchema = createSuccessSchema(z.object({ installUrl: z.string() }));
export const authorizeResponseSchema = createSuccessSchema(z.object({ authorizeUrl: z.string() }));
export const installationListResponseSchema = createSuccessSchema(
  z.object({ items: z.array(installationDto) }),
);
export const workspaceIntegrationResponseSchema = createSuccessSchema(
  z.object({
    configured: z.boolean(),
    linkingEnabled: z.boolean(),
    items: z.array(workspaceLinkDto),
  }),
);
export const workspaceLinkResponseSchema = createSuccessSchema(workspaceLinkDto);
const discoveryCandidate = z.object({
  externalInstallationId: z.string(),
  account,
  repositorySelection: z.enum(["all", "selected"]),
  suspended: z.boolean(),
  eligible: z.boolean(),
  reason: z.literal("not_owner").nullable(),
  alreadyLinkedHere: z.boolean(),
});
/** 200 answer of `POST /integrations/github/links` for a `discover` state: nothing is linked. */
export const discoveryResponseSchema = createSuccessSchema(
  z.object({
    mode: z.literal("discover"),
    truncated: z.boolean(),
    candidates: z.array(discoveryCandidate),
  }),
);
export const unlinkResponseSchema = createSuccessSchema(
  z.object({ unlinked: z.literal(true), repositoriesDisconnected: z.number() }),
);
export const deliveryListResponseSchema = createPaginatedSchema(deliveryDto);
export const allowListResponseSchema = createPaginatedSchema(allowListItem);
export const allowListUpdateResponseSchema = createSuccessSchema(
  z.object({ allowListCount: z.number(), added: z.number(), removed: z.number() }),
);
export const settingsResponseSchema = createSuccessSchema(
  z.object({
    allowWorkspaceLinking: z.boolean(),
    updatedAt: z.string().nullable(),
    updatedByUserId: z.string().nullable(),
  }),
);
