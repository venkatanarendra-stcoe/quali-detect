import { createLinkStateStore } from "../../lib/link-state.js";
import { API_PREFIX, MODULE_NAME } from "./constants/index.js";
import { createIntegrationController } from "./controllers/index.js";
import { createIntegrationRepository } from "./repositories/index.js";
import { integrationRoutes } from "./routes/index.js";
import { createIntegrationService } from "./services/index.js";

/** @param {import("../../runtime/modules.js").ModuleContext} app */
async function integrationsPlugin(app) {
  const service = createIntegrationService({
    repository: createIntegrationRepository({ db: app.infra.db }),
    scm: app.scm,
    stateStore: createLinkStateStore({
      infra: app.infra,
      ttlSeconds: app.config.scm?.linkStateTtlSeconds,
    }),
    audit: app.audit,
    outbox: app.outbox,
  });
  await app.register(integrationRoutes(createIntegrationController({ service }), app.authz));
}

/** @type {import("../../runtime/modules.js").ApiModule} */
export const integrationsModule = {
  name: MODULE_NAME,
  description:
    "Integrations catalog, tenant settings, the read-only installation view and the workspace-level GitHub lifecycle: link (verified), allow-list, refresh, unlink.",
  prefix: API_PREFIX,
  plugin: integrationsPlugin,
};
