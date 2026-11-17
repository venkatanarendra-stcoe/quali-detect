import { OPENAPI_TAG } from "../constants/index.js";
import {
  noQuerySchema,
  preferencesResponseSchema,
  updatePreferencesBodySchema,
} from "../schemas/index.js";

/**
 * The caller's own preferences. Tenant audience (the tenant comes from the session only). No permission: every
 * authenticated tenant user reads and writes only their own, and no path, query or body field names a user or a tenant.
 * @param {ReturnType<typeof import("../controllers/index.js").createUserPreferenceController>} controller
 * @returns {import("../../../lib/route-kit.js").RouteRegistrarFn}
 */
export const userPreferenceRoutes = (controller) =>
  async function userPreferences(app) {
    const tag = [OPENAPI_TAG];
    const config = { audience: "tenant" };
    app.get(
      "/me/preferences",
      {
        config,
        schema: {
          tags: tag,
          querystring: noQuerySchema,
          summary: "My preferences in the active tenant (defaults when none were saved)",
          response: { 200: preferencesResponseSchema },
        },
      },
      controller.get,
    );
    app.put(
      "/me/preferences",
      {
        rateLimit: "write",
        config,
        schema: {
          tags: tag,
          summary: "Set my preferences (upsert of the supplied fields; idempotent)",
          querystring: noQuerySchema,
          body: updatePreferencesBodySchema,
          response: { 200: preferencesResponseSchema },
        },
      },
      controller.update,
    );
  };
