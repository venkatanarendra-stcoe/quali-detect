import { z } from "zod";
import { createPaginatedSchema, createSuccessSchema } from "@qmentisai/contracts";
import { searchText, uuidParams } from "../../../lib/http.js";
import { createCollectionQuerySchema } from "../../../lib/query.js";
import { SORTABLE_FIELDS } from "../constants/index.js";

export const workspaceParamsSchema = uuidParams("workspaceId");
export const memberParamsSchema = uuidParams("workspaceId", "userId");
export const listMembersQuerySchema = createCollectionQuerySchema({
  sortableFields: SORTABLE_FIELDS,
  defaultSort: [{ field: "name", direction: "asc" }],
  filters: { q: searchText },
});
const memberDto = z.object({
  userId: z.string(),
  email: z.string(),
  name: z.string(),
  status: z.string(),
  addedAt: z.string(),
});
export const memberResponseSchema = createSuccessSchema(memberDto);
export const memberListResponseSchema = createPaginatedSchema(memberDto);
export const removedResponseSchema = createSuccessSchema(
  z.object({ removed: z.literal(true), revokedAssignments: z.number() }),
);
