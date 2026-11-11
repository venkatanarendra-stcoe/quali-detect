import { z } from "zod";
import {
  extendZodWithOpenApi,
  OpenAPIRegistry,
  OpenApiGeneratorV3,
} from "@asteasolutions/zod-to-openapi";
import { apiErrorSchema } from "@qmentisai/contracts";
import { isZodSchema } from "./validation.js";

extendZodWithOpenApi(z);

const ERROR_DESCRIPTIONS = Object.freeze({
  400: "Validation failed (VALIDATION_FAILED / BAD_REQUEST)",
  401: "No valid session (UNAUTHENTICATED)",
  403: "Not permitted or tenant not active (FORBIDDEN, TENANT_SUSPENDED, ROLE_ESCALATION, ENTITLEMENT_REQUIRED, QUOTA_EXCEEDED)",
  404: "Not found, or not visible to the caller (RESOURCE_NOT_FOUND)",
  409: "Conflicts with current state (CONFLICT, ROLE_IN_USE, LAST_TENANT_ADMIN, IDEMPOTENCY_CONFLICT)",
  429: "Too many attempts (RATE_LIMITED)",
});
const SUCCESS_DESCRIPTIONS = Object.freeze({ 200: "OK", 201: "Created" });
const SECURITY_BY_AUDIENCE = Object.freeze({
  user: [{ tenantSession: [] }],
  tenant: [{ tenantSession: [] }],
  platform: [{ platformSession: [] }],
});

const json = (schema) => ({ content: { "application/json": { schema } } });

/** Express `:param` placeholders -> OpenAPI `{param}`. @param {string} url */
export const toOpenApiPath = (url) => url.replace(/:([A-Za-z0-9_]+)/g, "{$1}");

/**
 * Registers one route (from the route kit's table) in the registry: request parts and responses come from the SAME Zod
 * schemas that validate the request, the security requirement is implied by the audience, and the standard error envelope
 * is documented for the statuses that audience can produce (explicit response schemas win).
 * @param {OpenAPIRegistry} registry
 * @param {import("./route-kit.js").RouteRecord} route
 */
function registerRoute(registry, { method, url, audience, schema, idempotent, rateLimit }) {
  const request = {};
  if (idempotent)
    request.headers = z.object({
      "Idempotency-Key": z
        .string()
        .regex(/^[A-Za-z0-9._:-]{8,128}$/)
        .optional()
        .openapi({
          description:
            "Optional. Replays the stored response for the same tenant, user, route and request; reusing the key with a different request is 409 IDEMPOTENCY_CONFLICT.",
        }),
    });
  if (isZodSchema(schema.params)) request.params = schema.params;
  if (isZodSchema(schema.querystring)) request.query = schema.querystring;
  if (isZodSchema(schema.body)) request.body = { required: true, ...json(schema.body) };

  const responses = {};
  for (const [status, value] of Object.entries(schema.response ?? {})) {
    responses[status] = {
      description: SUCCESS_DESCRIPTIONS[status] ?? "Response",
      ...(isZodSchema(value) ? json(value) : {}),
    };
  }
  const statuses = [];
  if (isZodSchema(schema.params) || isZodSchema(schema.querystring) || isZodSchema(schema.body))
    statuses.push(400);
  if (audience !== "public") statuses.push(401, 403);
  if (audience === "tenant" || audience === "platform" || schema.params) statuses.push(404);
  if (audience === "public" && /\/auth\/(login|mfa\/verify)$/.test(url)) statuses.push(401);
  if (rateLimit || (audience === "public" && /\/auth\/(login|mfa\/verify)$/.test(url)))
    statuses.push(429);
  if (idempotent) statuses.push(400, 409);
  for (const status of new Set(statuses)) {
    responses[status] ??= { description: ERROR_DESCRIPTIONS[status], ...json(apiErrorSchema) };
  }

  registry.registerPath({
    method,
    path: toOpenApiPath(url),
    tags: schema.tags,
    summary: schema.summary,
    ...(SECURITY_BY_AUDIENCE[audience] ? { security: SECURITY_BY_AUDIENCE[audience] } : {}),
    ...(Object.keys(request).length > 0 ? { request } : {}),
    responses,
  });
}

/**
 * Generates the OpenAPI 3.0.3 document from the route kit's table (`@asteasolutions/zod-to-openapi`). Routes with
 * `schema.hide` are left out. The table is the single source: nothing is documented that is not routed, and vice versa.
 * @param {{ config: any, routes: import("./route-kit.js").RouteRecord[] }} input
 */
export function buildOpenApiDocument({ config, routes }) {
  const registry = new OpenAPIRegistry();
  registry.registerComponent("securitySchemes", "tenantSession", {
    type: "apiKey",
    in: "cookie",
    name: "qm_session",
  });
  registry.registerComponent("securitySchemes", "platformSession", {
    type: "apiKey",
    in: "cookie",
    name: "qm_platform_session",
  });
  for (const route of routes) {
    if (route.schema.hide) continue;
    registerRoute(registry, { ...route, method: route.method.toLowerCase() });
  }
  return new OpenApiGeneratorV3(registry.definitions).generateDocument({
    openapi: "3.0.3",
    info: {
      title: "QmentisAI API",
      version: config.app.version,
      description:
        "Versioned REST API (/api/v1). Responses use the standard success/error envelope. Authentication uses HttpOnly session cookies (tenant: qm_session, platform: qm_platform_session).",
    },
  });
}
