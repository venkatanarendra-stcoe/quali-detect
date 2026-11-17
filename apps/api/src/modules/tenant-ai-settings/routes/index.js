import { OPENAPI_TAG } from "../constants/index.js";
import {
  aiSettingsResponseSchema,
  noQuerySchema,
  updateAiSettingsBodySchema,
} from "../schemas/index.js";

/**
 * Tenant AI settings (data-egress consent for an external LLM provider). Tenant audience: the tenant comes from the session
 * only. Read with `tenant_settings.view`, change with `tenant_settings.manage`; others get 403 (the permission is a tenant
 * permission, so there is no hidden resource to 404).
 * @param {ReturnType<typeof import("../controllers/index.js").createTenantAiSettingsController>} controller
 * @param {{ authorize: Function }} authz
 * @returns {import("../../../lib/route-kit.js").RouteRegistrarFn}
 */
export const tenantAiSettingsRoutes = (controller, authz) =>
  async function tenantAiSettings(app) {
    const tags = [OPENAPI_TAG];
    const config = { audience: "tenant" };
    const view = authz.authorize("tenant_settings.view");
    const manage = authz.authorize("tenant_settings.manage");
    app.get(
      "/settings/ai",
      {
        config,
        preHandler: view,
        schema: {
          tags,
          summary: "AI assistant settings of the organization (external-provider consent)",
          querystring: noQuerySchema,
          response: { 200: aiSettingsResponseSchema },
        },
      },
      controller.get,
    );
    app.put(
      "/settings/ai",
      {
        config,
        rateLimit: "write",
        preHandler: manage,
        schema: {
          tags,
          summary:
            "Allow or forbid sending repository metadata (file paths) to an external AI provider (audited)",
          querystring: noQuerySchema,
          body: updateAiSettingsBodySchema,
          response: { 200: aiSettingsResponseSchema },
        },
      },
      controller.update,
    );
  };
