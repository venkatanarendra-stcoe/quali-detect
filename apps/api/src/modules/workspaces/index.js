import { API_PREFIX, MODULE_NAME } from "./constants/index.js";
import { createWorkspaceController } from "./controllers/index.js";
import { createWorkspaceRepository } from "./repositories/index.js";
import { workspaceRoutes } from "./routes/index.js";
import { createWorkspaceService } from "./services/index.js";

/** @type {import("fastify").FastifyPluginAsync} */
async function workspacesPlugin(app) {
  const repository = createWorkspaceRepository({ db: app.infra.db });
  const service = createWorkspaceService({
    repository,
    audit: app.audit,
    entitlements: app.entitlements,
  });
  await app.register(workspaceRoutes(createWorkspaceController({ service }), app.authz));
}

/** @type {import("../../plugins/modules.js").ApiModule} */
export const workspacesModule = {
  name: MODULE_NAME,
  description:
    "Workspaces of a tenant: create, update, archive and restore, with visibility from effective permissions.",
  prefix: API_PREFIX,
  plugin: workspacesPlugin,
};
