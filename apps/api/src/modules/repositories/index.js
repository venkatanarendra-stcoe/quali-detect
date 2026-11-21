import { createExecutionArtifactRepository } from "@qmentisai/db";
import { API_PREFIX, MODULE_NAME } from "./constants/index.js";
import { createPipelineCounts } from "../pipelines/index.js";
import { createRepositoryController } from "./controllers/index.js";
import { createRepositoryRepository } from "./repositories/index.js";
import { repositoryRoutes } from "./routes/index.js";
import { createRepositoryService } from "./services/index.js";

/** @param {import("../../runtime/modules.js").ModuleContext} app */
async function repositoriesPlugin(app) {
  const service = createRepositoryService({
    repository: createRepositoryRepository({ db: app.infra.db }),
    scm: app.scm,
    audit: app.audit,
    outbox: app.outbox,
    entitlements: app.entitlements,
    pipelineCounts: createPipelineCounts({ db: app.infra.db }),
    infra: app.infra,
    artifacts: createExecutionArtifactRepository({ db: app.infra.db }),
  });
  await app.register(repositoryRoutes(createRepositoryController({ service }), app.authz));
}

/** @type {import("../../runtime/modules.js").ApiModule} */
export const repositoriesModule = {
  name: MODULE_NAME,
  description:
    "Connected source repositories: list, connect, detail, edit, sync, enable/disable and soft disconnect, with workspace-scoped permissions.",
  prefix: API_PREFIX,
  plugin: repositoriesPlugin,
};
