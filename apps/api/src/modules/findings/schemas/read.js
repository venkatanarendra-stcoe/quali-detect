import { z } from "zod";
import { createSuccessSchema } from "@qmentisai/contracts";
import {
  commentDtoSchema,
  findingDetailSchema,
  findingListItemSchema,
  historyEntrySchema,
  similarFindingSchema,
  summaryDtoSchema,
} from "@qmentisai/shared";

/**
 * Response schemas of the read routes, for the OpenAPI document (docs/modules/findings/SPEC.md 8.4). The DTO shapes themselves are the
 * frozen contract of `@qmentisai/shared`; only the envelopes are composed here.
 */
const pagination = z.object({
  limit: z.number().int().min(1),
  nextCursor: z.string().nullable(),
  hasMore: z.boolean(),
  page: z.number().int().min(1).optional(),
  pageSize: z.number().int().min(1).optional(),
  totalItems: z.number().int().min(0).optional(),
  totalPages: z.number().int().min(0).optional(),
});
const listEnvelope = (item) =>
  z.object({
    success: z.literal(true),
    data: z.array(item),
    meta: z.object({ correlationId: z.string(), pagination }),
  });

export const readResponses = Object.freeze({
  list: listEnvelope(findingListItemSchema),
  summary: createSuccessSchema(summaryDtoSchema),
  detail: createSuccessSchema(findingDetailSchema),
  history: listEnvelope(historyEntrySchema),
  comments: listEnvelope(commentDtoSchema),
  similar: createSuccessSchema(z.array(similarFindingSchema)),
});
