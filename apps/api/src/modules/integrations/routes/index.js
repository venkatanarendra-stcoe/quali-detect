import { OPENAPI_TAG } from "../constants/index.js";
import {
  authorizeBodySchema,
  authorizeResponseSchema,
  catalogResponseSchema,
  deliveriesQuerySchema,
  deliveryListResponseSchema,
  githubOverviewResponseSchema,
  linkBodySchema,
  linkListResponseSchema,
  linkParamsSchema,
  linkResponseSchema,
  scopeBodySchema,
  startResponseSchema,
  unlinkBodySchema,
  unlinkResponseSchema,
} from "../schemas/index.js";

/**
 * Integration routes (tenant scope): `integration.view` reads, `integration.manage` changes. Linking follows the documented
 * GitHub sequence (SPEC §6.1): start -> authorize (our single-use state) -> link (verification).
 * @param {ReturnType<typeof import("../controllers/index.js").createIntegrationController>} controller
 * @param {{ authorize: Function }} authz
 * @returns {import("../../../lib/route-kit.js").RouteRegistrarFn}
 */
export const integrationRoutes = (controller, authz) =>
  async function integrations(app) {
    const tags = [OPENAPI_TAG];
    const config = { audience: "tenant" };
    const view = authz.authorize("integration.view");
    const manage = authz.authorize("integration.manage");
    app.get(
      "/integrations",
      {
        config,
        preHandler: view,
        schema: {
          tags,
          summary: "Integrations catalog (GitHub is live; the rest are listed as not available)",
          response: { 200: catalogResponseSchema },
        },
      },
      controller.catalog,
    );
    app.get(
      "/integrations/github",
      {
        config,
        preHandler: view,
        schema: {
          tags,
          summary: "GitHub integration overview",
          response: { 200: githubOverviewResponseSchema },
        },
      },
      controller.overview,
    );
    app.get(
      "/integrations/github/installations",
      {
        config,
        preHandler: view,
        schema: {
          tags,
          summary: "GitHub installations linked to this organization",
          response: { 200: linkListResponseSchema },
        },
      },
      controller.list,
    );
    app.post(
      "/integrations/github/installations/start",
      {
        config,
        rateLimit: "write",
        preHandler: manage,
        schema: {
          tags,
          summary: "Start linking: the GitHub page where the App is installed",
          response: { 200: startResponseSchema },
        },
      },
      controller.start,
    );
    app.post(
      "/integrations/github/installations/authorize",
      {
        config,
        rateLimit: "write",
        preHandler: manage,
        schema: {
          tags,
          summary:
            "After the setup redirect: create the single-use state and return GitHub's authorize URL",
          body: authorizeBodySchema,
          response: { 200: authorizeResponseSchema },
        },
      },
      controller.authorize,
    );
    app.post(
      "/integrations/github/installations",
      {
        config,
        rateLimit: "write",
        preHandler: manage,
        schema: {
          tags,
          summary:
            "Verify the user's authorization and link the installation (organization admin or account owner required)",
          body: linkBodySchema,
          response: { 201: linkResponseSchema },
        },
      },
      controller.link,
    );
    app.post(
      "/integrations/github/installations/:linkId/refresh",
      {
        config,
        rateLimit: "write",
        preHandler: manage,
        schema: {
          tags,
          summary: "Test the connection: re-read the installation and mint a token",
          params: linkParamsSchema,
          response: { 200: linkResponseSchema },
        },
      },
      controller.refresh,
    );
    app.put(
      "/integrations/github/installations/:linkId/workspaces",
      {
        config,
        preHandler: manage,
        schema: {
          tags,
          summary: "Set the workspaces allowed to use the connection (empty = all)",
          params: linkParamsSchema,
          body: scopeBodySchema,
          response: { 200: linkResponseSchema },
        },
      },
      controller.setScope,
    );
    app.get(
      "/integrations/github/installations/:linkId/deliveries",
      {
        config,
        preHandler: view,
        schema: {
          tags,
          summary: "Recent webhook deliveries of this installation (no payloads)",
          params: linkParamsSchema,
          querystring: deliveriesQuerySchema,
          response: { 200: deliveryListResponseSchema },
        },
      },
      controller.deliveries,
    );
    app.delete(
      "/integrations/github/installations/:linkId",
      {
        config,
        preHandler: manage,
        schema: {
          tags,
          summary: "Unlink the installation: repositories are disconnected, nothing is deleted",
          params: linkParamsSchema,
          body: unlinkBodySchema,
          response: { 200: unlinkResponseSchema },
        },
      },
      controller.unlink,
    );
  };
