import { API_PREFIX, MODULE_NAME } from "./constants/index.js";
import { createGroupController } from "./controllers/index.js";
import { createGroupRepository } from "./repositories/index.js";
import { groupRoutes } from "./routes/index.js";
import { createGroupService } from "./services/index.js";

/** @type {import("../../../lib/route-kit.js").RouteRegistrarFn} */
async function groupsPlugin(app) {
  const repository = createGroupRepository({ db: app.infra.db });
  const service = createGroupService({ repository, authz: app.authz.service, audit: app.audit });
  await app.register(groupRoutes(createGroupController({ service }), app.authz));
}

/** @type {import("../../runtime/modules.js").ApiModule} */
export const groupsModule = {
  name: MODULE_NAME,
  description: "Flat groups of tenant members and their membership.",
  prefix: API_PREFIX,
  plugin: groupsPlugin,
};
