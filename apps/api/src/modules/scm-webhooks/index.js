import { API_PREFIX, MODULE_NAME } from "./constants/index.js";
import { createWebhookController } from "./controllers/index.js";
import { createWebhookRepository } from "./repositories/index.js";
import { webhookRoutes } from "./routes/index.js";
import { createWebhookService } from "./services/index.js";

/** Registers the GitHub webhook route only when the integration is enabled. @param {import("../../runtime/modules.js").ModuleContext} app */
async function scmWebhooksPlugin(app) {
  if (!app.scm) return;
  const service = createWebhookService({
    repository: createWebhookRepository({ db: app.infra.db }),
    scm: app.scm,
    outbox: app.outbox,
    infra: app.infra,
    logger: app.log,
  });
  await app.register(
    webhookRoutes(createWebhookController({ service, logger: app.log }), app.scm.config),
  );
}

/** @type {import("../../runtime/modules.js").ApiModule} */
export const scmWebhooksModule = {
  name: MODULE_NAME,
  description:
    "GitHub App webhook ingestion: signature, installation-based tenant resolution, dedupe, normalized events through the outbox.",
  prefix: API_PREFIX,
  plugin: scmWebhooksPlugin,
};
