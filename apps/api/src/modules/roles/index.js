import { API_PREFIX, MODULE_NAME } from "./constants/index.js";
import { createRoleController } from "./controllers/index.js";
import { createRoleRepository } from "./repositories/index.js";
import { roleRoutes } from "./routes/index.js";
import { createRoleService } from "./services/index.js";

/** @type {import("../../../lib/route-kit.js").RouteRegistrarFn} */
async function rolesPlugin(app) {
  const repository = createRoleRepository({ db: app.infra.db });
  const service = createRoleService({ repository, authz: app.authz.service, audit: app.audit });
  await app.register(roleRoutes(createRoleController({ service }), app.authz));
}

/** @type {import("../../runtime/modules.js").ApiModule} */
export const rolesModule = {
  name: MODULE_NAME,
  description: "Permission catalog and custom roles (built-in roles are read-only).",
  prefix: API_PREFIX,
  plugin: rolesPlugin,
};
