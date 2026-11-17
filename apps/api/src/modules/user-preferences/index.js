import { API_PREFIX, MODULE_NAME } from "./constants/index.js";
import { createUserPreferenceController } from "./controllers/index.js";
import { createUserPreferenceRepository } from "./repositories/index.js";
import { userPreferenceRoutes } from "./routes/index.js";
import { createUserPreferenceService } from "./services/index.js";

/** @type {import("../../../lib/route-kit.js").RouteRegistrarFn} */
async function userPreferencesPlugin(app) {
  const repository = createUserPreferenceRepository({ db: app.infra.db });
  const service = createUserPreferenceService({ repository });
  await app.register(userPreferenceRoutes(createUserPreferenceController({ service })));
}

/** @type {import("../../runtime/modules.js").ApiModule} */
export const userPreferencesModule = {
  name: MODULE_NAME,
  description: "Interface preferences of the signed-in user (accent colour), per tenant.",
  prefix: API_PREFIX,
  plugin: userPreferencesPlugin,
};
