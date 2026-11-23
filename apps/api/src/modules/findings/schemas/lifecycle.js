import { z } from "zod";
import { createSuccessSchema } from "@qmentisai/contracts";
import {
  approvalQueueItemSchema,
  bulkResultSchema,
  commentDtoSchema,
  findingDetailSchema,
} from "@qmentisai/shared";

/**
 * Response schemas of the write routes and the Approvals queue, for the OpenAPI document (docs/modules/findings/SPEC.md 8.4). The DTO
 * shapes are the frozen contract of `@qmentisai/shared`; only the envelopes are composed here. A write answers with the finding detail
 * as the CALLER now sees it (including the per-caller `lifecycle.allowedActions`), the shape of the E mock.
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

export const lifecycleResponses = Object.freeze({
  finding: createSuccessSchema(findingDetailSchema),
  comment: createSuccessSchema(commentDtoSchema),
  bulk: createSuccessSchema(bulkResultSchema),
  approvals: z.object({
    success: z.literal(true),
    data: z.array(approvalQueueItemSchema),
    meta: z.object({ correlationId: z.string(), pagination }),
  }),
});
