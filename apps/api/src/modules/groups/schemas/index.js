import { z } from "zod";
import { createPaginatedSchema, createSuccessSchema } from "@qmentisai/contracts";
import { atLeastOne, searchText, text, uuidParams } from "../../../lib/http.js";
import { createCollectionQuerySchema } from "../../../lib/query.js";
import { MEMBER_SORTABLE_FIELDS, SORTABLE_FIELDS } from "../constants/index.js";

export const groupParamsSchema = uuidParams("groupId");
export const memberParamsSchema = uuidParams("groupId", "userId");
export const listGroupsQuerySchema = createCollectionQuerySchema({
  sortableFields: SORTABLE_FIELDS,
  defaultSort: [{ field: "name", direction: "asc" }],
  filters: { q: searchText },
});
export const listMembersQuerySchema = createCollectionQuerySchema({
  sortableFields: MEMBER_SORTABLE_FIELDS,
  defaultSort: [{ field: "name", direction: "asc" }],
  filters: { q: searchText },
});
export const createGroupBodySchema = z
  .object({ name: text(100), description: text(500).nullish() })
  .strict();
export const updateGroupBodySchema = atLeastOne(
  z.object({ name: text(100).optional(), description: text(500).nullable().optional() }),
);

const groupDto = z.object({
  id: z.string(),
  name: z.string(),
  description: z.string().nullable(),
  memberCount: z.number(),
  createdAt: z.string(),
  updatedAt: z.string(),
});
const memberDto = z.object({
  userId: z.string(),
  email: z.string(),
  name: z.string(),
  addedAt: z.string(),
});
export const groupResponseSchema = createSuccessSchema(groupDto);
export const groupListResponseSchema = createPaginatedSchema(groupDto);
export const memberResponseSchema = createSuccessSchema(memberDto);
export const memberListResponseSchema = createPaginatedSchema(memberDto);
export const deletedResponseSchema = createSuccessSchema(z.object({ deleted: z.literal(true) }));
export const removedResponseSchema = createSuccessSchema(z.object({ removed: z.literal(true) }));
