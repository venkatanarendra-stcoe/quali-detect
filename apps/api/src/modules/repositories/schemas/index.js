import { z } from "zod";
import { createPaginatedSchema, createSuccessSchema } from "@qmentisai/contracts";
import { atLeastOne, searchText, text, uuidParams } from "../../../lib/http.js";
import { createCollectionQuerySchema, paginationShape } from "../../../lib/query.js";
import { SORTABLE_FIELDS } from "../constants/index.js";

export const repositoryParamsSchema = uuidParams("repositoryId");
export const workspaceParamsSchema = uuidParams("workspaceId");
export const listRepositoriesQuerySchema = createCollectionQuerySchema({
  sortableFields: SORTABLE_FIELDS,
  defaultSort: [{ field: "fullName", direction: "asc" }],
  filters: {
    q: searchText,
    workspaceId: z.string().uuid().optional(),
    provider: z.enum(["github"]).optional(),
    status: z.enum(["active", "unavailable", "disconnected"]).optional(),
    health: z.enum(["healthy", "degraded", "error", "disconnected"]).optional(),
  },
});
export const availableQuerySchema = z
  .object({
    ...paginationShape({ defaultPageSize: 30, maxPageSize: 100 }),
    workspaceLinkId: z.string().uuid(),
    q: searchText,
    visibility: z.enum(["public", "private", "internal"]).optional(),
  })
  .strict();
export const connectBodySchema = z
  .object({
    workspaceLinkId: z.string().uuid(),
    externalRepoId: z.string().regex(/^\d{1,19}$/),
    displayName: text(100).nullish(),
    description: text(500).nullish(),
    ownerUserId: z.string().uuid().optional(),
  })
  .strict();
export const updateBodySchema = atLeastOne(
  z.object({
    displayName: text(100).nullable().optional(),
    description: text(500).nullable().optional(),
    ownerUserId: z.string().uuid().nullable().optional(),
  }),
);
export const disconnectBodySchema = z.object({ confirm: z.string().min(1).max(300) }).strict();

const repositoryDto = z.object({
  id: z.string(),
  workspaceId: z.string(),
  linkId: z.string(),
  workspaceLinkId: z.string(),
  provider: z.literal("github"),
  externalRepoId: z.string(),
  fullName: z.string(),
  name: z.string(),
  ownerLogin: z.string(),
  htmlUrl: z.string().nullable(),
  visibility: z.string(),
  defaultBranch: z.string().nullable(),
  description: z.string().nullable(),
  displayName: z.string().nullable(),
  ownerUserId: z.string().nullable(),
  status: z.enum(["active", "unavailable", "disconnected"]),
  enabled: z.boolean(),
  archived: z.boolean(),
  health: z.enum(["healthy", "degraded", "error", "disconnected"]),
  healthReason: z.string().nullable(),
  consecutiveSyncFailures: z.number(),
  lastSyncedAt: z.string().nullable(),
  lastEventAt: z.string().nullable(),
  connectedAt: z.string(),
  disconnectedAt: z.string().nullable(),
  disconnectReason: z.string().nullable(),
  pipelineCount: z.number().nullable(),
});
export const repositoryResponseSchema = createSuccessSchema(repositoryDto);
export const repositoryListResponseSchema = createPaginatedSchema(repositoryDto);
export const availableListResponseSchema = createPaginatedSchema(
  z.object({
    externalRepoId: z.string(),
    fullName: z.string(),
    visibility: z.string(),
    defaultBranch: z.string().nullable(),
    archived: z.boolean(),
    alreadyConnected: z.boolean(),
  }),
);
export const syncResponseSchema = createSuccessSchema(z.object({ status: z.literal("queued") }));
export const disconnectedResponseSchema = createSuccessSchema(
  z.object({ disconnected: z.literal(true) }),
);
export const branchesResponseSchema = createSuccessSchema(
  z.object({
    items: z.array(
      z.object({ name: z.string(), protected: z.boolean(), sha: z.string().nullable() }),
    ),
  }),
);
export const pullRequestsResponseSchema = createSuccessSchema(
  z.object({
    items: z.array(
      z.object({
        number: z.number(),
        title: z.string(),
        state: z.string(),
        draft: z.boolean().nullable(),
        authorLogin: z.string().nullable(),
        headRef: z.string().nullable(),
        baseRef: z.string().nullable(),
        headSha: z.string().nullable(),
        isFork: z.boolean(),
      }),
    ),
  }),
);
