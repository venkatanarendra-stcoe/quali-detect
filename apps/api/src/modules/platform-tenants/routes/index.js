import { OPENAPI_TAG } from "../constants/index.js";
import { lifecyclePolicy } from "../policies/index.js";
import {
  lifecycleBodySchema,
  listTenantsQuerySchema,
  planVersionsResponseSchema,
  provisionTenantBodySchema,
  tenantDetailResponseSchema,
  tenantListResponseSchema,
  tenantParamsSchema,
} from "../schemas/index.js";

/**
 * Root Console tenant routes (platform audience). Each route needs its own `platform.*` permission on top of the platform
 * session; a tenant principal never reaches them (404).
 * @param {ReturnType<typeof import("../controllers/index.js").createPlatformTenantController>} controller
 * @param {{ requirePlatformPermission: (key: string) => any }} auth
 * @returns {import("../../../lib/route-kit.js").RouteRegistrarFn}
 */
export const platformTenantRoutes = (controller, auth) =>
  async function platformTenants(app) {
    const tag = [OPENAPI_TAG];
    const config = { audience: "platform" };
    app.get(
      "/tenants",
      {
        config,
        preHandler: auth.requirePlatformPermission("platform.tenant.view"),
        schema: {
          tags: tag,
          summary: "List tenants (metadata and counts only)",
          querystring: listTenantsQuerySchema,
          response: { 200: tenantListResponseSchema },
        },
      },
      controller.list,
    );
    app.post(
      "/tenants",
      {
        config,
        preHandler: auth.requirePlatformPermission("platform.tenant.create"),
        schema: {
          tags: tag,
          summary: "Provision a tenant with its first administrator (invited)",
          body: provisionTenantBodySchema,
          response: { 201: tenantDetailResponseSchema },
        },
      },
      controller.provision,
    );
    app.get(
      "/tenants/:tenantId",
      {
        config,
        preHandler: auth.requirePlatformPermission("platform.tenant.view"),
        schema: {
          tags: tag,
          summary: "Tenant detail: subscription, usage counts, administrators, lifecycle",
          params: tenantParamsSchema,
          response: { 200: tenantDetailResponseSchema },
        },
      },
      controller.detail,
    );
    // One route per action so each carries exactly its own permission.
    for (const action of ["suspend", "reactivate", "deactivate", "restore"]) {
      app.post(
        `/tenants/:tenantId/${action}`,
        {
          config,
          preHandler: auth.requirePlatformPermission(lifecyclePolicy.permissionFor(action)),
          schema: {
            tags: tag,
            summary: `${action[0].toUpperCase()}${action.slice(1)} a tenant (reason required; audited)`,
            params: tenantParamsSchema,
            body: lifecycleBodySchema,
            response: { 200: tenantDetailResponseSchema },
          },
        },
        controller.lifecycle(action),
      );
    }
    app.get(
      "/plans",
      {
        config,
        preHandler: auth.requirePlatformPermission("platform.plan.view"),
        schema: {
          tags: tag,
          summary: "Published plan versions (for provisioning)",
          response: { 200: planVersionsResponseSchema },
        },
      },
      controller.plans,
    );
  };
