import { API_PREFIX, MODULE_NAME } from "./constants/index.js";
import { createRoleAssignmentController } from "./controllers/index.js";
import { createRoleAssignmentRepository } from "./repositories/index.js";
import { roleAssignmentRoutes } from "./routes/index.js";
import { createRoleAssignmentService } from "./services/index.js";

/** @type {import("../../../lib/route-kit.js").RouteRegistrarFn} */
async function roleAssignmentsPlugin(app) {
  const repository = createRoleAssignmentRepository({ db: app.infra.db });
  const service = createRoleAssignmentService({
    repository,
    authz: app.authz.service,
    audit: app.audit,
  });
  await app.register(roleAssignmentRoutes(createRoleAssignmentController({ service }), app.authz));
}

/** @type {import("../../runtime/modules.js").ApiModule} */
export const roleAssignmentsModule = {
  name: MODULE_NAME,
  description: "Role assignments to users and groups at tenant or workspace scope.",
  prefix: API_PREFIX,
  plugin: roleAssignmentsPlugin,
};
