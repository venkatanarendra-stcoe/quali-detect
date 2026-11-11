import { z } from "zod";
import { createPaginatedSchema, createSuccessSchema } from "@qmentisai/contracts";
import { createCollectionQuerySchema } from "../../../lib/query.js";

/** Public representation of a registered module. */
export const moduleDtoSchema = z.object({
  name: z.string(),
  description: z.string(),
  prefix: z.string(),
});

export const infoDtoSchema = z.object({
  name: z.string(),
  version: z.string(),
  environment: z.string(),
  apiVersion: z.string(),
});

/** Query of GET /system/modules: pagination, allow-listed sorting and one declared filter. */
export const listModulesQuerySchema = createCollectionQuerySchema({
  sortableFields: ["name", "prefix"],
  defaultSort: [{ field: "name", direction: "asc" }],
  filters: { search: z.string().trim().min(1).max(100).optional() },
});

export const moduleParamsSchema = z.object({ name: z.string().regex(/^[a-z][a-z0-9-]{0,63}$/) });

const readinessCheckSchema = z.object({ name: z.string(), status: z.enum(["up", "down"]) });

// Response envelopes (used for OpenAPI documentation).
export const healthResponseSchema = createSuccessSchema(z.object({ status: z.literal("ok") }));
export const readinessResponseSchema = createSuccessSchema(
  z.object({ status: z.literal("ready"), checks: z.array(readinessCheckSchema) }),
);
export const infoResponseSchema = createSuccessSchema(infoDtoSchema);
export const moduleResponseSchema = createSuccessSchema(moduleDtoSchema);
export const listModulesResponseSchema = createPaginatedSchema(moduleDtoSchema);
