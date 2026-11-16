import { createLogStore } from "@qmentisai/infra";
import { createExecutionLogRepository, LOG_CEILINGS } from "@qmentisai/db";
import { API_PREFIX, MODULE_NAME } from "./constants/index.js";
import { createExecutionController } from "./controllers/index.js";
import { executionActionPolicies } from "./policies/index.js";
import { createExecutionsRepository } from "./repositories/index.js";
import { executionRoutes } from "./routes/index.js";
import { createExecutionService } from "./services/index.js";
import { createExecutionReadService } from "./services/read.js";

export { MODULE_NAME, createExecutionService, createExecutionsRepository };

/** @param {import("../../runtime/modules.js").ModuleContext} app */
async function executionsPlugin(app) {
  const repository = createExecutionsRepository({ db: app.infra.db });
  const service = createExecutionService({
    repository,
    audit: app.audit,
    outbox: app.outbox,
    entitlements: app.entitlements,
    config: app.config.executions,
  });
  // Reads only: the caps below are the database ceilings and matter to writers (the workers), never to this process.
  const logStore = createLogStore({
    repository: createExecutionLogRepository({ db: app.infra.db }),
    limits: {
      maxLinesPerExecution: LOG_CEILINGS.executionLines,
      maxBytesPerExecution: LOG_CEILINGS.executionBytes,
      maxLinesPerTask: LOG_CEILINGS.taskLines,
      maxBytesPerTask: LOG_CEILINGS.taskBytes,
    },
  });
  const reads = createExecutionReadService({ repository, logStore });
  await app.register(
    executionRoutes(
      createExecutionController({ service, reads }),
      app.authz,
      executionActionPolicies({ authz: app.authz, service }),
    ),
  );
}

/** @type {import("../../runtime/modules.js").ApiModule} */
export const executionsModule = {
  name: MODULE_NAME,
  description:
    "Executions: list, detail, status history, logs, cancel and retry, tenant and workspace scoped with execution.* permissions.",
  prefix: API_PREFIX,
  plugin: executionsPlugin,
};
