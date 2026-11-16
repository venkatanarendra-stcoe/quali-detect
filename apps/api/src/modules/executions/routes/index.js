import { OPENAPI_TAG } from "../constants/index.js";
import {
  cancelBodySchema,
  eventsQuerySchema,
  executionParamsSchema,
  listQuerySchema,
  logsQuerySchema,
  responses,
  retryBodySchema,
  retryHeadersSchema,
} from "../schemas/index.js";

/**
 * Execution routes (SPEC executions §8.1). The collection is filtered to the workspaces where the caller holds
 * `execution.view` (never 403). Item routes use the execution scope resolver: an execution of another tenant, in a workspace
 * the caller cannot see, or that does not exist is the same 404; a visible execution without the permission is 403. Cancel and
 * retry are rate limited, accept `Idempotency-Key` (retry REQUIRES it) and audit a denial on a visible execution. There is no
 * route under `/api/v1/platform`: a platform session is refused by the route kit's authentication (401).
 * @param {ReturnType<typeof import("../controllers/index.js").createExecutionController>} controller
 * @param {{ authorize: Function, context: Function, scopes: any }} authz
 * @param {{ cancelPolicy: import("express").RequestHandler, retryPolicy: import("express").RequestHandler }} policies
 * @returns {import("../../../lib/route-kit.js").RouteRegistrarFn}
 */
export const executionRoutes = (controller, authz, policies) =>
  async function executions(app) {
    const tags = [OPENAPI_TAG];
    const config = { audience: "tenant" };
    const inWorkspace = (key) => authz.authorize(key, authz.scopes.execution());
    const params = executionParamsSchema;

    app.get(
      "/executions",
      {
        config,
        preHandler: authz.context,
        schema: {
          tags,
          summary:
            "List executions in the workspaces the caller can see (cursor-paginated, no totals)",
          querystring: listQuerySchema,
          response: { 200: responses.list },
        },
      },
      controller.list,
    );
    app.get(
      "/executions/:executionId",
      {
        config,
        preHandler: inWorkspace("execution.view"),
        schema: {
          tags,
          summary: "Get an execution with its tasks, counts, timings and snapshot summary",
          params,
          response: { 200: responses.detail },
        },
      },
      controller.get,
    );
    app.get(
      "/executions/:executionId/events",
      {
        config,
        preHandler: inWorkspace("execution.view"),
        schema: {
          tags,
          summary: "Status history of an execution, oldest first (cursor-paginated)",
          params,
          querystring: eventsQuerySchema,
          response: { 200: responses.events },
        },
      },
      controller.events,
    );
    app.get(
      "/executions/:executionId/logs",
      {
        config,
        rateLimit: "read",
        preHandler: inWorkspace("execution.view"),
        schema: {
          tags,
          summary: "Log lines of an execution (redacted at write time; afterSeq or cursor)",
          params,
          querystring: logsQuerySchema,
          response: { 200: responses.logs },
        },
      },
      controller.logs,
    );
    app.post(
      "/executions/:executionId/cancel",
      {
        config,
        rateLimit: "write",
        idempotent: true,
        preHandler: policies.cancelPolicy,
        schema: {
          tags,
          summary:
            "Cancel an execution: 200 when a queued one was cancelled, 202 when a request was recorded (mode comes from the snapshot)",
          params,
          body: cancelBodySchema,
          response: { 200: responses.cancelled, 202: responses.cancelRequested },
        },
      },
      controller.cancel,
    );
    app.post(
      "/executions/:executionId/retry",
      {
        config,
        rateLimit: "write",
        idempotent: true,
        preHandler: policies.retryPolicy,
        schema: {
          tags,
          summary:
            "Retry an execution as a NEW execution with the same snapshot and commit (Idempotency-Key is REQUIRED)",
          params,
          headers: retryHeadersSchema,
          body: retryBodySchema,
          response: { 202: responses.retried },
        },
      },
      controller.retry,
    );
  };
