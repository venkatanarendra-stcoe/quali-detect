import { OPENAPI_TAG } from "../constants/index.js";
import {
  platformLoginBodySchema,
  platformLoginResponseSchema,
  platformLogoutResponseSchema,
  platformMeResponseSchema,
  platformMfaBodySchema,
  platformMfaResponseSchema,
} from "../schemas/index.js";

/**
 * Root Console identity routes under /api/v1/platform. Login/logout are public; /me needs a platform session.
 * @param {ReturnType<typeof import("../controllers/index.js").createPlatformIdentityController>} controller
 * @returns {import("fastify").FastifyPluginAsync}
 */
export const platformIdentityRoutes = (controller) =>
  async function platformIdentity(app) {
    const tag = [OPENAPI_TAG];
    app.post(
      "/auth/login",
      {
        config: { audience: "public" },
        schema: {
          tags: tag,
          summary: "Platform sign in (mock provider)",
          body: platformLoginBodySchema,
          response: { 200: platformLoginResponseSchema },
        },
      },
      controller.login,
    );
    app.post(
      "/auth/mfa/verify",
      {
        config: { audience: "public" },
        schema: {
          tags: tag,
          summary: "Complete mandatory MFA (mock: 6-digit code); issues a new verified session",
          body: platformMfaBodySchema,
          response: { 200: platformMfaResponseSchema },
        },
      },
      controller.verifyMfa,
    );
    app.post(
      "/auth/logout",
      {
        config: { audience: "public" },
        schema: {
          tags: tag,
          summary: "Platform sign out (idempotent)",
          response: { 200: platformLogoutResponseSchema },
        },
      },
      controller.logout,
    );
    app.get(
      "/me",
      {
        config: { audience: "platform" },
        schema: {
          tags: tag,
          summary: "Current platform user, role and platform permissions",
          response: { 200: platformMeResponseSchema },
        },
      },
      controller.me,
    );
  };
