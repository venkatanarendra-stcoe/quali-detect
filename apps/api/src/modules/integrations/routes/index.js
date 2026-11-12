import { OPENAPI_TAG } from "../constants/index.js";
import {
  allowListBodySchema,
  allowListQuerySchema,
  allowListResponseSchema,
  allowListUpdateResponseSchema,
  authorizeBodySchema,
  authorizeResponseSchema,
  catalogResponseSchema,
  deliveriesQuerySchema,
  deliveryListResponseSchema,
  githubOverviewResponseSchema,
  installationListResponseSchema,
  linkBodySchema,
  linkParamsSchema,
  settingsBodySchema,
  settingsResponseSchema,
  startResponseSchema,
  unlinkBodySchema,
  unlinkResponseSchema,
  workspaceIntegrationResponseSchema,
  workspaceLinkParamsSchema,
  workspaceLinkResponseSchema,
  workspaceParamsSchema,
} from "../schemas/index.js";

/**
 * Integration routes (SPEC §18, ADR-012). Tenant scope is READ-ONLY for GitHub (`integration.view`: catalog, installations,
 * deliveries, settings); `integration.manage` only changes the tenant setting. Linking, allow-list, test connection and
 * unlink are workspace-scoped (`workspace_integration.view` / `.manage`, evaluated in the workspace of the URL). Consuming
 * a linking state has no workspace in the URL: the service re-checks the permission in the state's workspace.
 * @param {ReturnType<typeof import("../controllers/index.js").createIntegrationController>} controller
 * @param {{ authorize: Function, context: Function, scopes: any }} authz
 * @returns {import("../../../lib/route-kit.js").RouteRegistrarFn}
 */
export const integrationRoutes = (controller, authz) =>
  async function integrations(app) {
    const tags = [OPENAPI_TAG];
    const config = { audience: "tenant" };
    const view = authz.authorize("integration.view");
    const manage = authz.authorize("integration.manage");
    const wsView = authz.authorize("workspace_integration.view", authz.scopes.workspace());
    const wsManage = authz.authorize("workspace_integration.manage", authz.scopes.workspace());
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
      "/integrations/settings",
      {
        config,
        preHandler: view,
        schema: {
          tags,
          summary: "Tenant source-control settings (allow workspace admins to link source control)",
          response: { 200: settingsResponseSchema },
        },
      },
      controller.getSettings,
    );
    app.put(
      "/integrations/settings",
      {
        config,
        rateLimit: "write",
        preHandler: manage,
        schema: {
          tags,
          summary: "Turn workspace-level linking of source control on or off for the organization",
          body: settingsBodySchema,
          response: { 200: settingsResponseSchema },
        },
      },
      controller.updateSettings,
    );
    app.get(
      "/integrations/github/installations",
      {
        config,
        preHandler: view,
        schema: {
          tags,
          summary:
            "GitHub installations of this organization and the workspaces using them (read-only)",
          response: { 200: installationListResponseSchema },
        },
      },
      controller.listInstallations,
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
    app.post(
      "/integrations/github/links",
      {
        config,
        rateLimit: "write",
        preHandler: authz.context,
        schema: {
          tags,
          summary:
            "Verify the user's authorization and link the installation to the workspace of the state (organization admin or account owner required)",
          body: linkBodySchema,
          response: { 201: workspaceLinkResponseSchema },
        },
      },
      controller.link,
    );
    app.get(
      "/workspaces/:workspaceId/integrations/github",
      {
        config,
        preHandler: wsView,
        schema: {
          tags,
          summary: "This workspace's GitHub connections",
          params: workspaceParamsSchema,
          response: { 200: workspaceIntegrationResponseSchema },
        },
      },
      controller.workspaceOverview,
    );
    app.post(
      "/workspaces/:workspaceId/integrations/github/start",
      {
        config,
        rateLimit: "write",
        preHandler: wsManage,
        schema: {
          tags,
          summary: "Start linking: the GitHub page where the App is installed",
          params: workspaceParamsSchema,
          response: { 200: startResponseSchema },
        },
      },
      controller.start,
    );
    app.post(
      "/workspaces/:workspaceId/integrations/github/authorize",
      {
        config,
        rateLimit: "write",
        preHandler: wsManage,
        schema: {
          tags,
          summary:
            "After the setup redirect: create the single-use state (bound to this workspace) and return GitHub's authorize URL",
          params: workspaceParamsSchema,
          body: authorizeBodySchema,
          response: { 200: authorizeResponseSchema },
        },
      },
      controller.authorize,
    );
    app.post(
      "/workspaces/:workspaceId/integrations/github/links/:linkId/refresh",
      {
        config,
        rateLimit: "write",
        preHandler: wsManage,
        schema: {
          tags,
          summary: "Test the connection: re-read the installation and mint a token",
          params: workspaceLinkParamsSchema,
          response: { 200: workspaceLinkResponseSchema },
        },
      },
      controller.refresh,
    );
    app.delete(
      "/workspaces/:workspaceId/integrations/github/links/:linkId",
      {
        config,
        rateLimit: "write",
        preHandler: wsManage,
        schema: {
          tags,
          summary:
            "Disconnect this workspace from the installation: only its repositories are disconnected, nothing is deleted",
          params: workspaceLinkParamsSchema,
          body: unlinkBodySchema,
          response: { 200: unlinkResponseSchema },
        },
      },
      controller.unlink,
    );
    app.get(
      "/workspaces/:workspaceId/integrations/github/links/:linkId/repositories",
      {
        config,
        preHandler: wsView,
        schema: {
          tags,
          summary:
            "Repositories the installation can access (live, paged) with this workspace's allow-list flag",
          params: workspaceLinkParamsSchema,
          querystring: allowListQuerySchema,
          response: { 200: allowListResponseSchema },
        },
      },
      controller.listAllowList,
    );
    app.put(
      "/workspaces/:workspaceId/integrations/github/links/:linkId/repositories",
      {
        config,
        rateLimit: "write",
        preHandler: wsManage,
        schema: {
          tags,
          summary: "Replace or patch the repositories this workspace may connect (allow-list)",
          params: workspaceLinkParamsSchema,
          body: allowListBodySchema,
          response: { 200: allowListUpdateResponseSchema },
        },
      },
      controller.setAllowList,
    );
  };
