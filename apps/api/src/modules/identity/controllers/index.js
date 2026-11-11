import { clearSessionCookie, readSessionCookie, setSessionCookie } from "../../../auth/cookies.js";

/**
 * HTTP adapters of the identity module: read validated input, call the service, manage the session cookie, send the envelope.
 * @param {{ service: ReturnType<typeof import("../services/index.js").createIdentityService>, config: any, auth: any }} deps
 */
export function createIdentityController({ service, config, auth }) {
  return {
    login: async (request, reply) => {
      const previous = await auth.sessions.tenant.resolve(
        readSessionCookie(request, "tenant", config),
      );
      const { token, session, ...data } = await service.login({
        ...request.body,
        ip: request.ip,
        userAgent: request.headers["user-agent"],
        requestId: request.id,
        previousSessionId: previous?.id,
      });
      setSessionCookie(reply, "tenant", config, token, session.expiresAt);
      return reply.success(data);
    },
    /** Public and idempotent: revokes the presented session if there is one and always clears the cookie. */
    logout: async (request, reply) => {
      const session = await auth.sessions.tenant.resolve(
        readSessionCookie(request, "tenant", config),
      );
      await service.logout({ session, requestId: request.id, ip: request.ip });
      clearSessionCookie(reply, "tenant", config);
      return reply.success({ loggedOut: true });
    },
    me: async (request, reply) => {
      // "user" audience: the tenant is optional here. When the session has one it must be usable (suspended => 403).
      const { principal } = request;
      const tenantContext = principal.session.activeTenantId
        ? await auth.resolvers.resolveTenantContext(principal)
        : {};
      return reply.success(await service.getMe({ principal: { ...principal, ...tenantContext } }));
    },
    myPermissions: async (request, reply) => {
      const tenantContext = await auth.resolvers.resolveTenantContext(request.principal);
      return reply.success(
        await service.getMyPermissions({
          principal: { ...request.principal, ...tenantContext },
          workspaceId: request.query.workspaceId,
        }),
      );
    },
    listInvitations: async (request, reply) =>
      reply.success(await service.listInvitations({ userId: request.principal.user.id })),
    acceptInvitation: async (request, reply) =>
      reply.success(
        await service.acceptInvitation({
          userId: request.principal.user.id,
          tenantId: request.params.tenantId,
          requestId: request.id,
          ip: request.ip,
        }),
      ),
    listTenants: async (request, reply) =>
      reply.success(await service.listTenants({ userId: request.principal.user.id })),
    switchTenant: async (request, reply) =>
      reply.success(
        await service.switchTenant({
          session: request.principal.session,
          userId: request.principal.user.id,
          tenantId: request.body.tenantId,
          requestId: request.id,
          ip: request.ip,
        }),
      ),
  };
}
