import { API_PREFIX, MODULE_NAME } from "./constants/index.js";
import { createIdentityController } from "./controllers/index.js";
import { registerIdentityListeners } from "./listeners/index.js";
import { createIdentityRepository } from "./repositories/index.js";
import { identityRoutes } from "./routes/index.js";
import { createIdentityService } from "./services/index.js";

/**
 * Module plugin: repository -> service -> controller -> routes, built from app decorators (no globals).
 * @type {import("../../../lib/route-kit.js").RouteRegistrarFn}
 */
async function identityPlugin(app) {
  const repository = createIdentityRepository({ db: app.infra.db });
  const service = createIdentityService({
    repository,
    auth: app.auth,
    authz: app.authz.service,
    audit: app.audit,
  });
  const controller = createIdentityController({ service, config: app.config, auth: app.auth });
  registerIdentityListeners(app);
  await app.register(identityRoutes(controller));
}

/** @type {import("../../runtime/modules.js").ApiModule} */
export const identityModule = {
  name: MODULE_NAME,
  description:
    "Mock authentication, sessions, the current user (/me), tenant selection, invitations and effective permissions.",
  prefix: API_PREFIX,
  plugin: identityPlugin,
};
