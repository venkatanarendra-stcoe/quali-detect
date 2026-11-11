import cookieParser from "cookie-parser";
import cors from "cors";
import { getPermission } from "@qmentisai/shared";
import { ERROR_CODES } from "@qmentisai/contracts";
import { AppError, ForbiddenError, NotFoundError } from "../errors/app-error.js";
import { createAuthAudit } from "../auth/audit.js";
import { createAuthResolvers } from "../auth/context.js";
import { createAuthProviders } from "../auth/providers/index.js";
import { createLoginThrottle } from "../auth/login-throttle.js";
import { createThrottleNotifier } from "../auth/throttle-notifier.js";
import { createSessionService } from "../auth/session-service.js";
import { createSessionStore } from "../auth/session-store.js";
import { createMemoryRateLimiter } from "../lib/memory-rate-limiter.js";

const UNSAFE_METHODS = new Set(["POST", "PUT", "PATCH", "DELETE"]);
export const PLATFORM_PREFIX = "/api/v1/platform/";
export const AUDIENCES = Object.freeze(["public", "user", "tenant", "platform"]);

/**
 * Authentication and tenant/platform context for the whole API (ADR-007: hooks became middleware).
 *
 * Every route MUST declare `config: { audience }` (enforced at startup by the route kit, `lib/route-kit.js`):
 * - "public":   no session (probes, login endpoints, OpenAPI);
 * - "user":     a tenant-audience session; the tenant is optional (profile, tenant switching);
 * - "tenant":   a tenant session AND an active, usable tenant derived ONLY from that session (never from request input);
 * - "platform": a platform session (Root Console). Only these and "public" routes may live under /api/v1/platform/.
 * Tenant and platform sessions are different cookies, tables and resolvers: one never authenticates the other, and the
 * two surfaces are separate Express routers with their own authentication middleware (`middleware.tenant`, `middleware.platform`).
 * Unsafe methods are checked against the allowed browser origins (CSRF defense on top of SameSite=Lax cookies).
 *
 * @param {{ db: any, config: any, audit: any, infra: any, logger: import("pino").Logger }} deps
 */
export function createAuthentication({ db, config, audit, infra, logger }) {
  if (!db) throw new Error("The identity module requires DATABASE_URL.");

  const sessions = Object.freeze({
    tenant: createSessionService({ store: createSessionStore({ db, kind: "tenant" }), config }),
    platform: createSessionService({ store: createSessionStore({ db, kind: "platform" }), config }),
  });
  const limiter = infra.rateLimiter ?? createMemoryRateLimiter();
  if (!infra.rateLimiter)
    logger.warn("Redis is not configured: login throttling is per process (development only)");

  const resolvers = createAuthResolvers({ db, config, sessions });

  const authAudit = createAuthAudit({ audit });
  const { throttle } = config.auth;
  const throttleBase = {
    limiter,
    decaySeconds: throttle.decaySeconds,
    ipFreeMultiplier: throttle.ipFreeMultiplier,
    onCapReached: createThrottleNotifier({ db, audit: authAudit, logger }),
  };
  const auth = Object.freeze({
    sessions,
    resolvers,
    providers: createAuthProviders({ db, config }),
    audit: authAudit,
    throttles: Object.freeze({
      tenant: createLoginThrottle({ ...throttleBase, audience: "tenant", policy: throttle.login }),
      platform: createLoginThrottle({
        ...throttleBase,
        audience: "platform",
        policy: throttle.login,
      }),
      // Second-factor guessing is far more valuable to an attacker than password guessing: a tighter curve (ADR-010).
      platformMfa: createLoginThrottle({
        ...throttleBase,
        audience: "platform-mfa",
        policy: throttle.mfa,
      }),
    }),
    /**
     * Route middleware for platform routes that need a specific platform permission (checked in addition to the platform session).
     * @param {string} key a `platform.*` permission key
     */
    requirePlatformPermission(key) {
      if (getPermission(key)?.scope !== "platform")
        throw new TypeError(`"${key}" is not a platform permission`);
      return Object.assign(
        function requirePlatformPermissionMiddleware(req, _res, next) {
          if (!req.principal?.platform?.permissions.includes(key))
            return next(new ForbiddenError());
          next();
        },
        { permission: key },
      );
    },
  });

  /** Adds identifying fields to the request logger (pino-http child). */
  const bindLog = (req, fields) => {
    if (req.log) req.log = req.log.child(fields);
  };

  /** Tenant-audience session -> `req.principal = { audience, session, user }`. For "user" and "tenant" routes. */
  const session = (audience) =>
    async function tenantSession(req, _res, next) {
      const principal = await resolvers.resolveUserSession(req);
      if (!principal) throw new AppError(ERROR_CODES.UNAUTHENTICATED, "Sign in to continue.");
      req.principal = { audience, ...principal };
      bindLog(req, { userId: principal.user.id });
      next();
    };

  /** Tenant context from `principal.session.activeTenantId` ONLY. For "tenant" routes. */
  const tenantContext = async function tenantContextMiddleware(req, _res, next) {
    Object.assign(req.principal, await resolvers.resolveTenantContext(req.principal));
    bindLog(req, { tenantId: req.principal.tenant.id });
    next();
  };

  /** Platform-audience session -> `req.principal = { audience: "platform", platform }`. */
  const platformSession = async function platformSessionMiddleware(req, _res, next) {
    const platform = await resolvers.resolvePlatformContext(req);
    if (!platform) {
      // A valid TENANT session must not learn that platform routes exist (404); no session at all is a 401.
      if (await resolvers.resolveUserSession(req).catch(() => null)) throw new NotFoundError();
      throw new AppError(ERROR_CODES.UNAUTHENTICATED, "Sign in to continue.");
    }
    req.principal = { audience: "platform", platform };
    bindLog(req, { platformUserId: platform.platformUser.id });
    next();
  };

  /** CORS (credentialed, exact origin list) -- global, before anything reads the request. */
  const corsMiddleware = cors({
    origin: [...config.auth.allowedOrigins],
    credentials: true,
    methods: ["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE"],
    maxAge: 600,
  });

  /** CSRF: a browser always sends Origin on cross-site unsafe requests; reject any that is not an allowed app origin. */
  const csrfOrigin = function csrfOriginMiddleware(req, _res, next) {
    const origin = req.headers.origin;
    if (UNSAFE_METHODS.has(req.method) && origin && !config.auth.allowedOrigins.includes(origin))
      return next(new ForbiddenError("Cross-site request rejected."));
    next();
  };

  return {
    auth,
    middleware: Object.freeze({
      cors: corsMiddleware,
      cookies: cookieParser(),
      csrfOrigin,
      /** Authentication chains per audience, in execution order. `public` has none. */
      chains: Object.freeze({
        public: Object.freeze([]),
        user: Object.freeze([session("user")]),
        tenant: Object.freeze([session("tenant"), tenantContext]),
        platform: Object.freeze([platformSession]),
      }),
    }),
  };
}
