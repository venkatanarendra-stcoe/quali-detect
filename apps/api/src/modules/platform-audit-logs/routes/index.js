import { OPENAPI_TAG } from "../constants/index.js";
import {
  listPlatformAuditLogsQuerySchema,
  platformAuditLogListResponseSchema,
} from "../schemas/index.js";

/**
 * Platform audit log under /api/v1/platform: a platform session AND `platform.audit_log.view` (Super Admin only by default).
 * @param {ReturnType<typeof import("../controllers/index.js").createPlatformAuditLogController>} controller
 * @param {{ requirePlatformPermission: (key: string) => Function }} auth
 * @returns {import("../../../lib/route-kit.js").RouteRegistrarFn}
 */
export const platformAuditLogRoutes = (controller, auth) =>
  async function platformAuditLogs(app) {
    app.get(
      "/audit-logs",
      {
        config: { audience: "platform" },
        preHandler: auth.requirePlatformPermission("platform.audit_log.view"),
        schema: {
          tags: [OPENAPI_TAG],
          summary:
            "List the platform audit log (newest first; filter by actor, action, tenant, date range, result)",
          querystring: listPlatformAuditLogsQuerySchema,
          response: { 200: platformAuditLogListResponseSchema },
        },
      },
      controller.list,
    );
  };
