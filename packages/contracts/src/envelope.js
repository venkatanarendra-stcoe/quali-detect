import { z } from "zod";

/**
 * Common event/message envelope (docs/technical/EVENT_CONTRACTS.md). Each event type must define its own
 * required fields and payload schema on top of this base.
 */
export const eventEnvelopeSchema = z.object({
  messageId: z.string(),
  eventType: z.string(),
  schemaVersion: z.number().int().positive(),
  occurredAt: z.string().datetime(),
  tenantId: z.string().optional(),
  workspaceId: z.string().optional(),
  repositoryId: z.string().optional(),
  pipelineId: z.string().optional(),
  executionId: z.string().optional(),
  correlationId: z.string(),
  actor: z.object({ type: z.string(), id: z.string() }).optional(),
  payload: z.record(z.unknown()),
});

/**
 * Pagination block of a collection response `meta` (Recommended shape; the docs require pagination but do not fix the fields).
 */
export const paginationMetaSchema = z.object({
  page: z.number().int().min(1),
  pageSize: z.number().int().min(1),
  totalItems: z.number().int().min(0),
  totalPages: z.number().int().min(0),
});

/** API response envelope (docs/technical/API_STANDARDS.md). */
export const apiSuccessSchema = z.object({
  success: z.literal(true),
  data: z.unknown(),
  meta: z.object({ correlationId: z.string() }),
});

/** Error envelope. `details` is optional and carries safe, structured context (for example field issues). */
export const apiErrorSchema = z.object({
  success: z.literal(false),
  error: z.object({
    code: z.string(),
    message: z.string(),
    details: z.record(z.unknown()).optional(),
  }),
  meta: z.object({ correlationId: z.string() }),
});

/**
 * Builds the success envelope schema for a given `data` schema (used for OpenAPI response documentation).
 * @param {import("zod").ZodTypeAny} dataSchema
 */
export function createSuccessSchema(dataSchema) {
  return z.object({
    success: z.literal(true),
    data: dataSchema,
    meta: z.object({ correlationId: z.string() }),
  });
}

/**
 * Builds the success envelope schema for a paginated collection of `itemSchema`.
 * @param {import("zod").ZodTypeAny} itemSchema
 */
export function createPaginatedSchema(itemSchema) {
  return z.object({
    success: z.literal(true),
    data: z.array(itemSchema),
    meta: z.object({ correlationId: z.string(), pagination: paginationMetaSchema }),
  });
}
