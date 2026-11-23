import { z } from "zod";
import { createSuccessSchema } from "@qmentisai/contracts";
import { boardDtoSchema, boardColumnSchema, slaSettingsDtoSchema } from "@qmentisai/shared";

/**
 * Response schemas of the remediation board and the SLA settings, for the OpenAPI document (docs/modules/findings/SPEC.md 8.4). The DTO
 * shapes are the frozen contract of `@qmentisai/shared` (the board card gained the optional PR link and ticket key, owner decision
 * 2026-11-24); only the envelopes are composed here. The write routes answer with `lifecycleResponses.finding` (Part B).
 */
const cardSchema = boardColumnSchema.shape.items.element;

export const remediationResponses = Object.freeze({
  board: createSuccessSchema(boardDtoSchema),
  column: z.object({
    success: z.literal(true),
    data: z.array(cardSchema),
    meta: z.object({
      correlationId: z.string(),
      pagination: z.object({
        limit: z.number().int().min(1),
        nextCursor: z.string().nullable(),
        hasMore: z.boolean(),
      }),
    }),
  }),
  sla: createSuccessSchema(slaSettingsDtoSchema),
});
