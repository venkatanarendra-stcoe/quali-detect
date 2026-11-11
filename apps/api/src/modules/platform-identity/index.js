import { API_PREFIX, MODULE_NAME } from "./constants/index.js";
import { createPlatformIdentityController } from "./controllers/index.js";
import { createPlatformIdentityRepository } from "./repositories/index.js";
import { platformIdentityRoutes } from "./routes/index.js";
import { createPlatformIdentityService } from "./services/index.js";

/**
 * Root Console identity. Slimmer than a tenant module on purpose: it has no policies, events or listeners yet, and reuses the
 * auth core (sessions, providers, throttling) with the platform audience, cookie and table.
 * @type {import("fastify").FastifyPluginAsync}
 */
async function platformIdentityPlugin(app) {
  const repository = createPlatformIdentityRepository({ db: app.infra.db });
  const service = createPlatformIdentityService({ repository, auth: app.auth });
  await app.register(
    platformIdentityRoutes(
      createPlatformIdentityController({ service, config: app.config, auth: app.auth }),
    ),
  );
}

/** @type {import("../../plugins/modules.js").ApiModule} */
export const platformIdentityModule = {
  name: MODULE_NAME,
  description:
    "Root Console (platform) sign-in and the current platform user; separate sessions from tenant users.",
  prefix: API_PREFIX,
  plugin: platformIdentityPlugin,
};
