import fp from "fastify-plugin";
import swagger from "@fastify/swagger";
import { swaggerTransform } from "../lib/openapi.js";

/**
 * Generates the OpenAPI document from route schemas (Zod, converted by `swaggerTransform`) and serves it as JSON at
 * `/api/v1/openapi.json`. Enabled by OPENAPI_ENABLED (default: on outside production).
 */
export default fp(
  async function openapiPlugin(app) {
    if (!app.config.openapi.enabled) return;
    await app.register(swagger, {
      openapi: {
        openapi: "3.0.3",
        info: {
          title: "QmentisAI API",
          version: app.config.app.version,
          description:
            "Versioned REST API (/api/v1). Responses use the standard success/error envelope. Authentication uses HttpOnly session cookies (tenant: qm_session, platform: qm_platform_session).",
        },
        components: {
          securitySchemes: {
            tenantSession: { type: "apiKey", in: "cookie", name: "qm_session" },
            platformSession: { type: "apiKey", in: "cookie", name: "qm_platform_session" },
          },
        },
      },
      transform: swaggerTransform,
    });
    app.get(
      "/api/v1/openapi.json",
      { config: { audience: "public" }, schema: { hide: true } },
      async () => app.swagger(),
    );
  },
  { name: "openapi", dependencies: [] },
);
