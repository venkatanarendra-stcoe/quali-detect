import { API_PREFIX, MODULE_NAME } from "./constants/index.js";
import { createUserController } from "./controllers/index.js";
import { createUserRepository } from "./repositories/index.js";
import { userRoutes } from "./routes/index.js";
import { createUserService } from "./services/index.js";

/** @type {import("fastify").FastifyPluginAsync} */
async function usersPlugin(app) {
  const repository = createUserRepository({ db: app.infra.db });
  const service = createUserService({
    repository,
    authz: app.authz.service,
    audit: app.audit,
    entitlements: app.entitlements,
  });
  await app.register(userRoutes(createUserController({ service }), app.authz));
}

/** @type {import("../../plugins/modules.js").ApiModule} */
export const usersModule = {
  name: MODULE_NAME,
  description:
    "Tenant members: invite, suspend, reactivate, remove and explain effective permissions.",
  prefix: API_PREFIX,
  plugin: usersPlugin,
};
