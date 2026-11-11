import { ipKeyGenerator, rateLimit } from "express-rate-limit";
import { RedisStore } from "rate-limit-redis";
import { ERROR_CODES } from "@qmentisai/contracts";
import { AppError } from "../errors/app-error.js";
import { createHash } from "node:crypto";

export const RATE_LIMIT_PROFILES = Object.freeze(["auth", "write", "webhook"]);

/**
 * Per-route rate limiting (on top of the global per-IP limit). A route opts in with `rateLimit: "<profile>"`; limits come
 * from configuration (`RATE_LIMIT_<PROFILE>_*`). Every route gets its OWN counter, so a busy route cannot exhaust another.
 *
 * - "auth" (public sign-in endpoints) and "webhook": counted per client IP;
 * - "write" (authenticated create/side-effect endpoints): counted per tenant + user (per platform user on the platform
 *   surface), so one tenant's traffic never affects another's.
 * Redis-backed when Redis is configured (shared across instances; the store is created on the first request, after the
 * lazy connection is up, and the limit fails OPEN with a warning if Redis is unreachable); in-process otherwise.
 * A refusal is `429 RATE_LIMITED` with `details.scope: "route"` and the standard `RateLimit`/`Retry-After` headers.
 * @param {{ config: any, infra: { redis: any }, logger?: import("pino").Logger }} deps
 */
export function createRouteLimiters({ config, infra, logger }) {
  const subjectOf = (profile, req) => {
    const principal = req.principal;
    if (profile === "write" && principal?.tenant)
      return `t:${principal.tenant.id}:u:${principal.user.id}`;
    if (profile === "write" && principal?.platform)
      return `p:${principal.platform.platformUser.id}`;
    return `ip:${ipKeyGenerator(req.ip ?? "unknown")}`;
  };

  /** @param {"auth" | "write" | "webhook"} profile @param {string} routeId e.g. "POST /api/v1/workspaces" */
  function forRoute(profile, routeId) {
    const limits = config.http.routeLimits[profile];
    if (!limits) throw new TypeError(`Unknown rate limit profile "${profile}".`);
    const slug = createHash("sha256").update(routeId).digest("hex").slice(0, 12);
    const build = (store) =>
      rateLimit({
        windowMs: limits.windowMs,
        limit: limits.max,
        standardHeaders: "draft-7",
        legacyHeaders: false,
        store,
        keyGenerator: (req) => subjectOf(profile, req),
        validate: { keyGeneratorIpFallback: false },
        handler: (_req, res, next) =>
          next(
            new AppError(ERROR_CODES.RATE_LIMITED, "Too many requests. Try again later.", {
              details: {
                scope: "route",
                profile,
                retryAfterSeconds: Number(res.getHeader("Retry-After")) || undefined,
              },
            }),
          ),
      });
    if (!infra.redis) return build(undefined);
    let limiter;
    return async function routeLimiter(req, res, next) {
      if (!limiter) {
        limiter = (async () => {
          try {
            await infra.redis.ping();
            return build(
              new RedisStore({
                prefix: `qm:rl:route:${profile}:${slug}:`,
                sendCommand: (...args) => infra.redis.call(...args),
              }),
            );
          } catch (error) {
            logger?.warn(
              { err: error, routeId },
              "Route rate limit disabled: Redis is unreachable",
            );
            limiter = undefined;
            return null;
          }
        })();
      }
      const active = await limiter;
      return active ? active(req, res, next) : next();
    };
  }
  return Object.freeze({ forRoute });
}
