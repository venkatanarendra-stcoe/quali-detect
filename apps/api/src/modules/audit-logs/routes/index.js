import { OPENAPI_TAG } from "../constants/index.js";
import { auditLogListResponseSchema, listAuditLogsQuerySchema } from "../schemas/index.js";

/**
 * Tenant audit log: `audit_log.view_all` is a tenant permission, so callers without it get 403, and the tenant is always
 * the session's.
 * @param {ReturnType<typeof import("../controllers/index.js").createAuditLogController>} controller
 * @param {{ authorize: Function }} authz
 * @returns {import("../../../lib/route-kit.js").RouteRegistrarFn}
 */
export const auditLogRoutes = (controller, authz) =>
  async function auditLogs(app) {
    app.get(
      "/audit-logs",
      {
        config: { audience: "tenant" },
        preHandler: authz.authorize("audit_log.view_all"),
        schema: {
          tags: [OPENAPI_TAG],
          summary:
            "List the tenant audit log (newest first; filter by actor, action, date range, result)",
          querystring: listAuditLogsQuerySchema,
          response: { 200: auditLogListResponseSchema },
        },
      },
      controller.list,
    );
  };
