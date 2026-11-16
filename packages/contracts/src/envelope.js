import { z } from "zod";

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

/**
 * Pagination block of a cursor-capable collection: the offset fields (unchanged) plus `nextCursor` (opaque; null on the last
 * page) and `hasMore`. Offset requests receive the same two fields, so a client can start in either mode.
 */
export const cursorPaginationMetaSchema = paginationMetaSchema.extend({
  nextCursor: z.string().nullable(),
  hasMore: z.boolean(),
});

/**
 * Paginated envelope of a cursor-capable collection.
 * @param {import("zod").ZodTypeAny} itemSchema
 */
export function createCursorPaginatedSchema(itemSchema) {
  return z.object({
    success: z.literal(true),
    data: z.array(itemSchema),
    meta: z.object({ correlationId: z.string(), pagination: cursorPaginationMetaSchema }),
  });
}

/**
 * Pagination block of a CURSOR-ONLY collection (no offset fields, no totals): `limit`, the opaque `nextCursor` (null on the last
 * page) and `hasMore`. Used by lists that never count (docs/modules/executions/SPEC.md CF-10).
 */
export const cursorOnlyPaginationMetaSchema = z.object({
  limit: z.number().int().min(1),
  nextCursor: z.string().nullable(),
  hasMore: z.boolean(),
});

/**
 * Envelope of a cursor-only collection of `itemSchema`.
 * @param {import("zod").ZodTypeAny} itemSchema
 */
export function createCursorOnlySchema(itemSchema) {
  return z.object({
    success: z.literal(true),
    data: z.array(itemSchema),
    meta: z.object({ correlationId: z.string(), pagination: cursorOnlyPaginationMetaSchema }),
  });
}
