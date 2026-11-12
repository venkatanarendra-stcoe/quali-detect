import { OPENAPI_TAG } from "../constants/index.js";
import {
  decisionsQuerySchema,
  executionsQuerySchema,
  listPipelinesQuerySchema,
  listRepositoryPipelinesQuerySchema,
  pipelineParamsSchema,
  repositoryParamsSchema,
  versionParamsSchema,
  versionsQuerySchema,
  workspaceParamsSchema,
} from "../schemas/index.js";

/**
 * Pipeline routes (SPEC §8). Collection: only pipelines in workspaces where the caller holds pipeline.view (never 403). Item
 * routes use the pipeline scope resolver and repository-parented routes the repository scope resolver: a pipeline or
 * repository of another tenant, or in a workspace the caller cannot see, is the same 404; visible but not permitted is 403.
 * Mutations are rate limited and accept Idempotency-Key; the manual run REQUIRES it. There is no route that updates or
 * deletes a configuration version: versions are immutable and an edit publishes a new one.
 * @param {ReturnType<typeof import("../controllers/index.js").createPipelineController>} controller
 * @param {ReturnType<typeof import("../schemas/index.js").createPipelineSchemas>} schemas
 * @param {{ authorize: Function, context: Function, scopes: any }} authz
 * @param {{ runPolicy: import("express").RequestHandler }} policies
 * @returns {import("../../../lib/route-kit.js").RouteRegistrarFn}
 */
export const pipelineRoutes = (controller, schemas, authz, policies) =>
  async function pipelines(app) {
    const tags = [OPENAPI_TAG];
    const config = { audience: "tenant" };
    const r = schemas.responses;
    const onPipeline = (key) => authz.authorize(key, authz.scopes.pipeline());
    const onRepository = (key) => authz.authorize(key, authz.scopes.repository());
    const write = { rateLimit: "write", idempotent: true };

    app.get(
      "/pipelines",
      {
        config,
        preHandler: authz.context,
        schema: {
          tags,
          summary: "List pipelines in the workspaces the caller can see",
          querystring: listPipelinesQuerySchema,
          response: { 200: r.pipelineList },
        },
      },
      controller.list,
    );
    app.get(
      "/repositories/:repositoryId/pipelines",
      {
        config,
        preHandler: onRepository("pipeline.view"),
        schema: {
          tags,
          summary: "List the pipelines of a repository",
          params: repositoryParamsSchema,
          querystring: listRepositoryPipelinesQuerySchema,
          response: { 200: r.pipelineList },
        },
      },
      controller.listForRepository,
    );
    app.post(
      "/repositories/:repositoryId/pipelines",
      {
        config,
        ...write,
        preHandler: onRepository("pipeline.manage"),
        schema: {
          tags,
          summary:
            "Create a pipeline (and its first configuration version) on an active repository",
          params: repositoryParamsSchema,
          body: schemas.createBody,
          response: { 201: r.pipeline },
        },
      },
      controller.create,
    );
    app.post(
      "/repositories/:repositoryId/pipelines/test-triggers",
      {
        config,
        rateLimit: "write",
        preHandler: onRepository("pipeline.view"),
        schema: {
          tags,
          summary: "Dry-run: which triggers would match a sample event (no side effects)",
          params: repositoryParamsSchema,
          body: schemas.dryRunBody,
          response: { 200: r.dryRun },
        },
      },
      controller.dryRun,
    );
    app.get(
      "/workspaces/:workspaceId/pipelines/options",
      {
        config,
        preHandler: authz.authorize("pipeline.view", authz.scopes.workspace()),
        schema: {
          tags,
          summary: "Platform limits and allowed values for the pipeline wizard",
          params: workspaceParamsSchema,
          response: { 200: r.options },
        },
      },
      controller.options,
    );
    app.get(
      "/pipelines/:pipelineId",
      {
        config,
        preHandler: onPipeline("pipeline.view"),
        schema: {
          tags,
          summary: "Get a pipeline",
          params: pipelineParamsSchema,
          response: { 200: r.pipeline },
        },
      },
      controller.get,
    );
    app.patch(
      "/pipelines/:pipelineId",
      {
        config,
        preHandler: onPipeline("pipeline.manage"),
        schema: {
          tags,
          summary: "Edit name or description (not versioned)",
          params: pipelineParamsSchema,
          body: schemas.updateBody,
          response: { 200: r.pipeline },
        },
      },
      controller.update,
    );
    app.get(
      "/pipelines/:pipelineId/versions",
      {
        config,
        preHandler: onPipeline("pipeline.view"),
        schema: {
          tags,
          summary: "List configuration versions",
          params: pipelineParamsSchema,
          querystring: versionsQuerySchema,
          response: { 200: r.versionList },
        },
      },
      controller.listVersions,
    );
    app.get(
      "/pipelines/:pipelineId/versions/:version",
      {
        config,
        preHandler: onPipeline("pipeline.view"),
        schema: {
          tags,
          summary: "Get one immutable configuration version",
          params: versionParamsSchema,
          response: { 200: r.version },
        },
      },
      controller.getVersion,
    );
    app.put(
      "/pipelines/:pipelineId/config",
      {
        config,
        ...write,
        preHandler: onPipeline("pipeline.manage"),
        schema: {
          tags,
          summary:
            "Publish configuration version N+1 (needs pipeline.manage_fork_policy to set a fork policy other than skip)",
          params: pipelineParamsSchema,
          body: schemas.configBody,
          response: { 200: r.published },
        },
      },
      controller.publishConfig,
    );
    app.post(
      "/pipelines/:pipelineId/enable",
      {
        config,
        ...write,
        preHandler: onPipeline("pipeline.manage"),
        schema: {
          tags,
          summary: "Enable a pipeline",
          params: pipelineParamsSchema,
          response: { 200: r.pipeline },
        },
      },
      controller.enable,
    );
    app.post(
      "/pipelines/:pipelineId/disable",
      {
        config,
        ...write,
        preHandler: onPipeline("pipeline.manage"),
        schema: {
          tags,
          summary: "Disable a pipeline",
          params: pipelineParamsSchema,
          response: { 200: r.pipeline },
        },
      },
      controller.disable,
    );
    app.delete(
      "/pipelines/:pipelineId",
      {
        config,
        preHandler: onPipeline("pipeline.delete"),
        schema: {
          tags,
          summary:
            "Soft delete a pipeline (history and findings stay; refused while executions are running)",
          params: pipelineParamsSchema,
          body: schemas.deleteBody,
          response: { 200: r.deleted },
        },
      },
      controller.remove,
    );
    app.post(
      "/pipelines/:pipelineId/runs",
      {
        config,
        ...write,
        preHandler: policies.runPolicy,
        schema: {
          tags,
          summary: "Manual run (Idempotency-Key is REQUIRED); creates one queued execution request",
          params: pipelineParamsSchema,
          headers: schemas.runHeaders,
          body: schemas.runBody,
          response: { 202: r.run },
        },
      },
      controller.run,
    );
    app.get(
      "/pipelines/:pipelineId/executions",
      {
        config,
        preHandler: onPipeline("execution.view"),
        schema: {
          tags,
          summary: "Minimal list of the pipeline's execution requests",
          params: pipelineParamsSchema,
          querystring: executionsQuerySchema,
          response: { 200: r.executionList },
        },
      },
      controller.listExecutions,
    );
    app.get(
      "/pipelines/:pipelineId/trigger-decisions",
      {
        config,
        preHandler: onPipeline("execution.view"),
        schema: {
          tags,
          summary: "Events skipped by policy (fork, draft, state)",
          params: pipelineParamsSchema,
          querystring: decisionsQuerySchema,
          response: { 200: r.decisionList },
        },
      },
      controller.listDecisions,
    );
  };
