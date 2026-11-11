import cookie from "@fastify/cookie";
import cors from "@fastify/cors";
import fp from "fastify-plugin";
import { getPermission } from "@qmentisai/shared";
import { AppError, ForbiddenError, NotFoundError } from "../errors/app-error.js";
import { ERROR_CODES } from "@qmentisai/contracts";
import { createAuthAudit } from "../auth/audit.js";
import { createAuthResolvers } from "../auth/context.js";
import { createAuthProviders } from "../auth/providers/index.js";
import { createLoginThrottle } from "../auth/login-throttle.js";
import { createSessionService } from "../auth/session-service.js";
import { createSessionStore } from "../auth/session-store.js";
import { createMemoryRateLimiter } from "../lib/memory-rate-limiter.js";

const UNSAFE_METHODS = new Set(["POST", "PUT", "PATCH", "DELETE"]);
const PLATFORM_PREFIX = "/api/v1/platform/";
export const AUDIENCES = Object.freeze(["public", "user", "tenant", "platform"]);

/**
 * Authentication and tenant/platform context for the whole API.
 *
 * Every route MUST declare `config: { audience }`:
 * - "public":   no session (probes, login endpoints, OpenAPI);
 * - "user":     a tenant-audience session; the tenant is optional (profile, tenant switching);
 * - "tenant":   a tenant session AND an active, usable tenant derived ONLY from that session (never from request input);
 * - "platform": a platform session (Root Console). Only these and "public" routes may live under /api/v1/platform/.
 * Routes without an audience, platform routes outside /api/v1/platform/, or tenant/user routes inside it fail at startup.
 * Tenant and platform sessions are different cookies, tables and resolvers: one never authenticates the other.
 * Unsafe methods are checked against the allowed browser origins (CSRF defense on top of SameSite=Lax cookies).
 */
export default fp(
  async function authenticationPlugin(app) {
    const { db } = app.infra;
    if (!db) throw new Error("The identity module requires DATABASE_URL.");
    const { config } = app;

    await app.register(cookie);
    await app.register(cors, {
      origin: [...config.auth.allowedOrigins],
      credentials: true,
      methods: ["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE"],
      maxAge: 600,
    });

    const sessions = Object.freeze({
      tenant: createSessionService({ store: createSessionStore({ db, kind: "tenant" }), config }),
      platform: createSessionService({
        store: createSessionStore({ db, kind: "platform" }),
        config,
      }),
    });
    const limiter = app.infra.rateLimiter ?? createMemoryRateLimiter();
    if (!app.infra.rateLimiter)
      app.log.warn("Redis is not configured: login throttling is per process (development only)");

    const resolvers = createAuthResolvers({ db, config, sessions });
    app.decorate(
      "auth",
      Object.freeze({
        sessions,
        resolvers,
        providers: createAuthProviders({ db, config }),
        audit: createAuthAudit({ audit: app.audit }),
        throttles: Object.freeze({
          tenant: createLoginThrottle({ limiter, audience: "tenant" }),
          platform: createLoginThrottle({ limiter, audience: "platform" }),
          // Second-factor guessing is far more valuable to an attacker than password guessing: tight per-user limit.
          platformMfa: createLoginThrottle({
            limiter,
            audience: "platform-mfa",
            perIdentity: 5,
            perIp: 30,
          }),
        }),
        /**
         * preHandler for platform routes that need a specific platform permission (checked in addition to the platform session).
         * @param {string} key a `platform.*` permission key
         */
        requirePlatformPermission(key) {
          if (getPermission(key)?.scope !== "platform")
            throw new TypeError(`"${key}" is not a platform permission`);
          return async function requirePlatformPermissionHook(request) {
            if (!request.principal?.platform?.permissions.includes(key)) throw new ForbiddenError();
          };
        },
      }),
    );
    app.decorateRequest("principal", null);

    app.addHook("onRoute", (route) => {
      const audience = route.config?.audience;
      const where = `${[route.method].flat().join(",")} ${route.url}`;
      if (!AUDIENCES.includes(audience))
        throw new Error(`Route ${where} must declare config.audience (${AUDIENCES.join(" | ")}).`);
      const underPlatform = route.url.startsWith(PLATFORM_PREFIX);
      if (audience === "platform" && !underPlatform)
        throw new Error(`Route ${where}: platform routes must live under ${PLATFORM_PREFIX}`);
      if ((audience === "user" || audience === "tenant") && underPlatform)
        throw new Error(`Route ${where}: tenant routes must not live under ${PLATFORM_PREFIX}`);
    });

    // CSRF: a browser always sends Origin on cross-site unsafe requests; reject any that is not an allowed app origin.
    app.addHook("onRequest", async (request) => {
      const origin = request.headers.origin;
      if (
        UNSAFE_METHODS.has(request.method) &&
        origin &&
        !config.auth.allowedOrigins.includes(origin)
      ) {
        throw new ForbiddenError("Cross-site request rejected.");
      }
    });

    app.addHook("preHandler", async (request) => {
      const audience = request.routeOptions.config?.audience;
      if (audience === "user" || audience === "tenant") {
        const principal = await resolvers.resolveUserSession(request);
        if (!principal) throw new AppError(ERROR_CODES.UNAUTHENTICATED, "Sign in to continue.");
        request.principal = { audience, ...principal };
        if (audience === "tenant") {
          // The tenant comes from principal.session.activeTenantId only.
          Object.assign(request.principal, await resolvers.resolveTenantContext(principal));
        }
        request.log = request.log.child({
          userId: principal.user.id,
          ...(request.principal.tenant ? { tenantId: request.principal.tenant.id } : {}),
        });
      } else if (audience === "platform") {
        const platform = await resolvers.resolvePlatformContext(request);
        if (!platform) {
          // A valid TENANT session must not learn that platform routes exist (404); no session at all is a 401.
          if (await resolvers.resolveUserSession(request).catch(() => null))
            throw new NotFoundError();
          throw new AppError(ERROR_CODES.UNAUTHENTICATED, "Sign in to continue.");
        }
        request.principal = { audience, platform };
        request.log = request.log.child({ platformUserId: platform.platformUser.id });
      }
    });
  },
  { name: "authentication", dependencies: ["infrastructure", "audit"] },
);
