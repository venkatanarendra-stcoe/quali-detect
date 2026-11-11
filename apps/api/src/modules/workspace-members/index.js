import { API_PREFIX, MODULE_NAME } from "./constants/index.js";
import { createWorkspaceMemberController } from "./controllers/index.js";
import { createWorkspaceMemberRepository } from "./repositories/index.js";
import { workspaceMemberRoutes } from "./routes/index.js";
import { createWorkspaceMemberService } from "./services/index.js";

/** @type {import("../../../lib/route-kit.js").RouteRegistrarFn} */
async function workspaceMembersPlugin(app) {
  const repository = createWorkspaceMemberRepository({ db: app.infra.db });
  const service = createWorkspaceMemberService({
    repository,
    authz: app.authz.service,
    audit: app.audit,
  });
  await app.register(
    workspaceMemberRoutes(createWorkspaceMemberController({ service }), app.authz),
  );
}

/** @type {import("../../runtime/modules.js").ApiModule} */
export const workspaceMembersModule = {
  name: MODULE_NAME,
  description: "Workspace rosters: add and remove tenant members of a workspace.",
  prefix: API_PREFIX,
  plugin: workspaceMembersPlugin,
};
