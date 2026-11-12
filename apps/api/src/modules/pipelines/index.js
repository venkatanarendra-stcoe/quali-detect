import { API_PREFIX, MODULE_NAME } from "./constants/index.js";
import { createPipelineController } from "./controllers/index.js";
import { manualRunPolicy } from "./policies/index.js";
import { createPipelineRepository } from "./repositories/index.js";
import { pipelineRoutes } from "./routes/index.js";
import { createPipelineSchemas } from "./schemas/index.js";
import { createPipelineService } from "./services/index.js";

/**
 * The repository DTO's `pipelineCount` provider (SPEC §7.6): non-deleted pipelines per repository, counted by the pipelines
 * module's repository layer with the tenant in every query.
 * @param {{ db: any }} deps
 */
export function createPipelineCounts({ db }) {
  const repository = createPipelineRepository({ db });
  return Object.freeze({
    /** @param {{ tenantId: string, repositoryIds: string[] }} input @returns {Promise<Map<string, number>>} */
    forRepositories: (input) => repository.countByRepository(input),
  });
}

/** @param {import("../../runtime/modules.js").ModuleContext} app */
async function pipelinesPlugin(app) {
  const repository = createPipelineRepository({ db: app.infra.db });
  const service = createPipelineService({
    repository,
    audit: app.audit,
    outbox: app.outbox,
    entitlements: app.entitlements,
    config: app.config.pipelines,
  });
  const schemas = createPipelineSchemas({ limits: app.config.pipelines.limits });
  await app.register(
    pipelineRoutes(createPipelineController({ service }), schemas, app.authz, {
      runPolicy: manualRunPolicy({ authz: app.authz, service, repository }),
    }),
  );
}

/** @type {import("../../runtime/modules.js").ApiModule} */
export const pipelinesModule = {
  name: MODULE_NAME,
  description:
    "Pipelines: versioned strict configuration, triggers, enable/disable, soft delete, manual runs, minimal execution requests, trigger decisions and dry-run, with workspace-scoped permissions.",
  prefix: API_PREFIX,
  plugin: pipelinesPlugin,
};
