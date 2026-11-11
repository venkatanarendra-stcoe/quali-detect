import { API_PREFIX, MODULE_NAME } from "./constants/index.js";
import { createAuditLogController } from "./controllers/index.js";
import { createAuditLogRepository } from "./repositories/index.js";
import { auditLogRoutes } from "./routes/index.js";
import { createAuditLogService } from "./services/index.js";

/** @param {import("../../runtime/modules.js").ModuleContext} app */
async function auditLogsPlugin(app) {
  const service = createAuditLogService({
    repository: createAuditLogRepository({ db: app.infra.db }),
  });
  await app.register(auditLogRoutes(createAuditLogController({ service }), app.authz));
}

/** @type {import("../../runtime/modules.js").ApiModule} */
export const auditLogsModule = {
  name: MODULE_NAME,
  description: "Read access to the tenant audit log (append-only; written by the other modules).",
  prefix: API_PREFIX,
  plugin: auditLogsPlugin,
};
