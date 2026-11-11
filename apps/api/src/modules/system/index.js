import { createSystemController } from "./controllers/index.js";
import { API_PREFIX, MODULE_NAME } from "./constants/index.js";
import { registerSystemListeners } from "./listeners/index.js";
import { systemPolicy } from "./policies/index.js";
import { createSystemRepository } from "./repositories/index.js";
import { apiRoutes, probeRoutes } from "./routes/index.js";
import { createSystemService } from "./services/index.js";

/**
 * Module plugin: builds the module's dependency graph from app decorators (no globals) and registers its routes.
 * Pattern for every module: repository -> service -> controller -> routes, plus policies, mappers, events, listeners.
 * @type {import("../../../lib/route-kit.js").RouteRegistrarFn}
 */
async function systemPlugin(app) {
  const repository = createSystemRepository({ modules: app.modules });
  const service = createSystemService({ repository, config: app.config, readiness: app.readiness });
  const controller = createSystemController({ service, policy: systemPolicy });

  registerSystemListeners(app);
  await app.register(probeRoutes(controller)); // /health, /ready at the root
  await app.register(apiRoutes(controller), { prefix: API_PREFIX }); // /api/v1/system/*
}

/**
 * The module descriptor registered in src/modules/index.js. The plugin mounts at the root because it owns both the
 * root probes and its own versioned prefix.
 * @type {import("../../runtime/modules.js").ApiModule}
 */
export const systemModule = {
  name: MODULE_NAME,
  description:
    "Operational endpoints: liveness, readiness, service information and the module registry.",
  prefix: "",
  plugin: systemPlugin,
};
