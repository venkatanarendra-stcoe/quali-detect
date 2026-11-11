import { clearSessionCookie, readSessionCookie, setSessionCookie } from "../../../auth/cookies.js";

/**
 * @param {{ service: ReturnType<typeof import("../services/index.js").createPlatformIdentityService>, config: any, auth: any }} deps
 */
export function createPlatformIdentityController({ service, config, auth }) {
  return {
    login: async (request, reply) => {
      const previous = await auth.sessions.platform.resolve(
        readSessionCookie(request, "platform", config),
      );
      const { token, session, ...data } = await service.login({
        ...request.body,
        ip: request.ip,
        userAgent: request.headers["user-agent"],
        requestId: request.id,
        previousSessionId: previous?.id,
      });
      setSessionCookie(reply, "platform", config, token, session.expiresAt);
      return reply.success(data);
    },
    /** Public route (it must accept a session that has NOT passed MFA): reads the platform cookie itself. */
    verifyMfa: async (request, reply) => {
      const current = await auth.sessions.platform.resolve(
        readSessionCookie(request, "platform", config),
      );
      const { token, session, ...data } = await service.verifyMfa({
        session: current,
        code: request.body.code,
        ip: request.ip,
        userAgent: request.headers["user-agent"],
        requestId: request.id,
      });
      setSessionCookie(reply, "platform", config, token, session.expiresAt);
      return reply.success(data);
    },
    logout: async (request, reply) => {
      const session = await auth.sessions.platform.resolve(
        readSessionCookie(request, "platform", config),
      );
      await service.logout({ session, requestId: request.id, ip: request.ip });
      clearSessionCookie(reply, "platform", config);
      return reply.success({ loggedOut: true });
    },
    me: async (request, reply) => reply.success(service.getMe({ principal: request.principal })),
  };
}
