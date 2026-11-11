import { OPENAPI_TAG } from "../constants/index.js";
import {
  acceptInvitationResponseSchema,
  invitationsResponseSchema,
  loginBodySchema,
  loginResponseSchema,
  logoutResponseSchema,
  meResponseSchema,
  myPermissionsResponseSchema,
  permissionsQuerySchema,
  tenantIdParamsSchema,
  switchTenantBodySchema,
  switchTenantResponseSchema,
  tenantsResponseSchema,
} from "../schemas/index.js";

/**
 * Identity routes under /api/v1. Each declares its audience (see middleware/authentication.js).
 * @param {ReturnType<typeof import("../controllers/index.js").createIdentityController>} controller
 * @returns {import("../../../lib/route-kit.js").RouteRegistrarFn}
 */
export const identityRoutes = (controller) =>
  async function identity(app) {
    const tag = [OPENAPI_TAG];
    app.post(
      "/auth/login",
      {
        rateLimit: "auth",
        config: { audience: "public" },
        schema: {
          tags: tag,
          summary: "Sign in (mock provider) and start a session cookie",
          body: loginBodySchema,
          response: { 200: loginResponseSchema },
        },
      },
      controller.login,
    );
    app.post(
      "/auth/logout",
      {
        rateLimit: "auth",
        config: { audience: "public" },
        schema: {
          tags: tag,
          summary: "Sign out: revoke the session and clear the cookie (idempotent)",
          response: { 200: logoutResponseSchema },
        },
      },
      controller.logout,
    );
    app.get(
      "/me",
      {
        config: { audience: "user" },
        schema: {
          tags: tag,
          summary: "Current user, active tenant and effective permissions per scope",
          response: { 200: meResponseSchema },
        },
      },
      controller.me,
    );
    app.get(
      "/me/permissions",
      {
        config: { audience: "user" },
        schema: {
          tags: tag,
          summary:
            "Effective permissions in the active tenant (advisory; optional workspace filter)",
          querystring: permissionsQuerySchema,
          response: { 200: myPermissionsResponseSchema },
        },
      },
      controller.myPermissions,
    );
    app.get(
      "/me/invitations",
      {
        config: { audience: "user" },
        schema: {
          tags: tag,
          summary: "Tenants that invited the current user",
          response: { 200: invitationsResponseSchema },
        },
      },
      controller.listInvitations,
    );
    app.post(
      "/me/invitations/:tenantId/accept",
      {
        rateLimit: "write",
        idempotent: true,
        config: { audience: "user" },
        schema: {
          tags: tag,
          summary: "Accept an invitation (the membership becomes active)",
          params: tenantIdParamsSchema,
          response: { 200: acceptInvitationResponseSchema },
        },
      },
      controller.acceptInvitation,
    );
    app.get(
      "/me/tenants",
      {
        config: { audience: "user" },
        schema: {
          tags: tag,
          summary: "Tenants the user can switch to",
          response: { 200: tenantsResponseSchema },
        },
      },
      controller.listTenants,
    );
    app.put(
      "/me/active-tenant",
      {
        config: { audience: "user" },
        schema: {
          tags: tag,
          summary: "Switch the session's active tenant",
          body: switchTenantBodySchema,
          response: { 200: switchTenantResponseSchema },
        },
      },
      controller.switchTenant,
    );
  };
