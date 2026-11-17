import { API_PREFIX, MODULE_NAME } from "./constants/index.js";
import { createTenantAiSettingsController } from "./controllers/index.js";
import { createTenantAiSettingsRepository } from "./repositories/index.js";
import { tenantAiSettingsRoutes } from "./routes/index.js";
import { createTenantAiSettingsService } from "./services/index.js";

/** @param {import("../../runtime/modules.js").ModuleContext} app */
async function tenantAiSettingsPlugin(app) {
  const service = createTenantAiSettingsService({
    repository: createTenantAiSettingsRepository({ db: app.infra.db }),
    audit: app.audit,
    llm: app.config.llm,
  });
  await app.register(
    tenantAiSettingsRoutes(createTenantAiSettingsController({ service }), app.authz),
  );
}

/** @type {import("../../runtime/modules.js").ApiModule} */
export const tenantAiSettingsModule = {
  name: MODULE_NAME,
  description: "Tenant AI settings: the audited data-egress consent for an external LLM provider.",
  prefix: API_PREFIX,
  plugin: tenantAiSettingsPlugin,
};
