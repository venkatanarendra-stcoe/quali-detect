import { API_PREFIX, MODULE_NAME } from "./constants/index.js";
import { createPlatformAuditLogController } from "./controllers/index.js";
import { createPlatformAuditLogRepository } from "./repositories/index.js";
import { platformAuditLogRoutes } from "./routes/index.js";
import { createPlatformAuditLogService } from "./services/index.js";

/** @param {import("../../runtime/modules.js").ModuleContext} app */
async function platformAuditLogsPlugin(app) {
  const service = createPlatformAuditLogService({
    repository: createPlatformAuditLogRepository({ db: app.infra.db }),
  });
  await app.register(
    platformAuditLogRoutes(createPlatformAuditLogController({ service }), app.auth),
  );
}

/** @type {import("../../runtime/modules.js").ApiModule} */
export const platformAuditLogsModule = {
  name: MODULE_NAME,
  description: "Read access to the platform audit log (Root Console).",
  prefix: API_PREFIX,
  plugin: platformAuditLogsPlugin,
};
