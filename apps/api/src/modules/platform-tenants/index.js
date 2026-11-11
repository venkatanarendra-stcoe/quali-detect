import { createAuthzRepository } from "../../authz/repository.js";
import { API_PREFIX, MODULE_NAME } from "./constants/index.js";
import { createPlatformTenantController } from "./controllers/index.js";
import { createPlatformTenantRepository } from "./repositories/index.js";
import { platformTenantRoutes } from "./routes/index.js";
import { createPlatformTenantService } from "./services/index.js";

/** @type {import("../../../lib/route-kit.js").RouteRegistrarFn} */
async function platformTenantsPlugin(app) {
  const { db } = app.infra;
  const repository = createPlatformTenantRepository({
    db,
    authzRepository: createAuthzRepository({ db }),
  });
  const service = createPlatformTenantService({ repository, audit: app.audit });
  await app.register(platformTenantRoutes(createPlatformTenantController({ service }), app.auth));
}

/** @type {import("../../runtime/modules.js").ApiModule} */
export const platformTenantsModule = {
  name: MODULE_NAME,
  description:
    "Root Console tenant management: list, provision, detail and lifecycle (suspend, reactivate, deactivate).",
  prefix: API_PREFIX,
  plugin: platformTenantsPlugin,
};
