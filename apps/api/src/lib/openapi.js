import { apiErrorSchema } from "@qmentisai/contracts";
import { zodToJsonSchema } from "zod-to-json-schema";
import { isZodSchema } from "./validation.js";

/**
 * Converts a Zod schema to an OpenAPI 3 compatible JSON Schema.
 * @param {import("zod").ZodTypeAny} schema
 */
export function toOpenApiSchema(schema) {
  const { $schema: _ignored, ...json } = zodToJsonSchema(schema, {
    target: "openApi3",
    $refStrategy: "none",
  });
  return json;
}

const REQUEST_PARTS = ["params", "querystring", "body", "headers"];

const ERROR_DESCRIPTIONS = Object.freeze({
  400: "Validation failed (VALIDATION_FAILED / BAD_REQUEST)",
  401: "No valid session (UNAUTHENTICATED)",
  403: "Not permitted or tenant not active (FORBIDDEN, TENANT_SUSPENDED, ROLE_ESCALATION, ENTITLEMENT_REQUIRED, QUOTA_EXCEEDED)",
  404: "Not found, or not visible to the caller (RESOURCE_NOT_FOUND)",
  409: "Conflicts with current state (CONFLICT, ROLE_IN_USE, LAST_TENANT_ADMIN)",
  429: "Too many attempts (RATE_LIMITED)",
});
const SECURITY_BY_AUDIENCE = Object.freeze({
  user: [{ tenantSession: [] }],
  tenant: [{ tenantSession: [] }],
  platform: [{ platformSession: [] }],
});
const errorBody = () => ({ ...toOpenApiSchema(apiErrorSchema), description: undefined });

/**
 * @fastify/swagger `transform` hook: turns the Zod schemas on a route into JSON Schema so OpenAPI is generated from
 * the same schemas that validate requests, adds the security requirement implied by the route's `config.audience`, and
 * documents the standard error envelope for the statuses that audience can produce (explicit response schemas win).
 * @param {{ schema?: Record<string, unknown>, url: string, route?: { config?: { audience?: string }, method?: string | string[] } }} input
 */
export function swaggerTransform({ schema, url, route }) {
  const converted = { ...schema };
  for (const part of REQUEST_PARTS) {
    if (isZodSchema(converted[part])) converted[part] = toOpenApiSchema(converted[part]);
  }
  const response = Object.fromEntries(
    Object.entries(converted.response ?? {}).map(([status, value]) => [
      status,
      isZodSchema(value) ? toOpenApiSchema(value) : value,
    ]),
  );
  const audience = route?.config?.audience;
  const statuses = [];
  if (REQUEST_PARTS.some((part) => converted[part])) statuses.push(400);
  if (audience && audience !== "public") statuses.push(401, 403);
  if (audience === "tenant" || audience === "platform" || converted.params) statuses.push(404);
  if (audience === "public" && /\/auth\/(login|mfa\/verify)$/.test(url)) statuses.push(401, 429);
  for (const status of [...new Set(statuses)]) {
    response[status] ??= { description: ERROR_DESCRIPTIONS[status], ...errorBody() };
  }
  if (Object.keys(response).length > 0) converted.response = response;
  if (audience && SECURITY_BY_AUDIENCE[audience])
    converted.security = SECURITY_BY_AUDIENCE[audience];
  return { schema: converted, url };
}
