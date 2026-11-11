import { OPENAPI_TAG } from "../constants/index.js";
import {
  healthResponseSchema,
  infoResponseSchema,
  listModulesQuerySchema,
  listModulesResponseSchema,
  moduleParamsSchema,
  moduleResponseSchema,
  readinessResponseSchema,
} from "../schemas/index.js";

/**
 * Operational probes, mounted at the root (unversioned, unauthenticated, no tenant data).
 * @param {ReturnType<typeof import("../controllers/index.js").createSystemController>} controller
 * @returns {import("fastify").FastifyPluginAsync}
 */
export const probeRoutes = (controller) =>
  async function probes(app) {
    app.get(
      "/health",
      {
        config: { audience: "public" },
        schema: {
          tags: [OPENAPI_TAG],
          summary: "Liveness probe",
          response: { 200: healthResponseSchema },
        },
      },
      controller.health,
    );
    app.get(
      "/ready",
      {
        config: { audience: "public" },
        schema: {
          tags: [OPENAPI_TAG],
          summary: "Readiness probe",
          response: { 200: readinessResponseSchema },
        },
      },
      controller.ready,
    );
  };

/**
 * Versioned module routes. Every route declares Zod schemas for what it accepts and returns; they validate input
 * and generate OpenAPI.
 * @param {ReturnType<typeof import("../controllers/index.js").createSystemController>} controller
 * @returns {import("fastify").FastifyPluginAsync}
 */
export const apiRoutes = (controller) =>
  async function api(app) {
    app.get(
      "/info",
      {
        config: { audience: "public" },
        schema: {
          tags: [OPENAPI_TAG],
          summary: "Service information",
          response: { 200: infoResponseSchema },
        },
      },
      controller.info,
    );
    app.get(
      "/modules",
      {
        config: { audience: "public" },
        schema: {
          tags: [OPENAPI_TAG],
          summary: "List registered modules (example collection endpoint)",
          querystring: listModulesQuerySchema,
          response: { 200: listModulesResponseSchema },
        },
      },
      controller.listModules,
    );
    app.get(
      "/modules/:name",
      {
        config: { audience: "public" },
        schema: {
          tags: [OPENAPI_TAG],
          summary: "Get one registered module",
          params: moduleParamsSchema,
          response: { 200: moduleResponseSchema },
        },
      },
      controller.getModule,
    );
  };
