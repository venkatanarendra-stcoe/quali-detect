import express from "express";
import helmet from "helmet";
import { rateLimit } from "express-rate-limit";
import { RedisStore } from "rate-limit-redis";
import { ERROR_CODES } from "@qmentisai/contracts";
import { AppError } from "../errors/app-error.js";

/**
 * Security response headers (helmet defaults: no sniffing, frame denial, strict CSP, HSTS). The API serves JSON only,
 * so the default restrictive Content-Security-Policy is correct; the optional Swagger UI mounts before this with its own policy.
 * @returns {import("express").RequestHandler}
 */
export const securityHeaders = () => helmet();

/**
 * Global per-IP request limit, applied before authentication (so it also covers unauthenticated floods). It is NOT
 * tenant-scoped on purpose: the tenant is unknown at this point. Login throttling (per identity and IP) is separate and
 * stricter. Backed by Redis when configured (shared across instances), otherwise memory (development only).
 * Probes are exempt so orchestrators are never throttled.
 * @param {{ config: any, infra: { redis: any } }} deps
 * @returns {import("express").RequestHandler}
 */
export function globalRateLimit({ config, infra, logger }) {
  const { windowMs, max } = config.http.rateLimit;
  const build = (store) =>
    rateLimit({
      windowMs,
      limit: max,
      standardHeaders: "draft-7",
      legacyHeaders: false,
      skip: (req) => req.path === "/health" || req.path === "/ready",
      store,
      handler: (_req, _res, next) =>
        next(new AppError(ERROR_CODES.RATE_LIMITED, "Too many requests. Try again later.")),
    });
  if (!infra.redis) return build(undefined);

  // The Redis client connects lazily and has no offline queue, so the store (which loads a Lua script when it is
  // created) is built on the first request, after the connection is up. If Redis is unreachable the global limit
  // fails open (logged) instead of taking the API down; login throttling is a separate control.
  let limiter;
  return async function globalRateLimitMiddleware(req, res, next) {
    if (!limiter) {
      limiter = (async () => {
        try {
          await infra.redis.ping();
          return build(
            new RedisStore({
              prefix: "qm:rl:global:",
              sendCommand: (...args) => infra.redis.call(...args),
            }),
          );
        } catch (error) {
          logger?.warn({ err: error }, "Global rate limit disabled: Redis is unreachable");
          limiter = undefined; // retry on a later request
          return null;
        }
      })();
    }
    const active = await limiter;
    return active ? active(req, res, next) : next();
  };
}

/** Paths whose body is read raw by their own route (see the route kit `webhook` option). */
export const WEBHOOK_PATH_PREFIX = "/api/v1/webhooks/";
const BODY_METHODS = new Set(["POST", "PUT", "PATCH", "DELETE"]);

/**
 * JSON body parsing with the configured size limit (413 PAYLOAD_TOO_LARGE, 400 on malformed JSON). A request that carries
 * a body of another content type is refused with 415 UNSUPPORTED_MEDIA_TYPE, as the Fastify transport did.
 * @param {{ config: any }} deps
 * @returns {import("express").RequestHandler[]}
 */
export function bodyParsing({ config }) {
  const guard = function contentTypeGuard(req, _res, next) {
    const hasBody =
      BODY_METHODS.has(req.method) &&
      (Number(req.headers["content-length"]) > 0 || req.headers["transfer-encoding"]);
    if (hasBody && !req.is("application/json"))
      return next(
        new AppError(
          ERROR_CODES.UNSUPPORTED_MEDIA_TYPE,
          "The request content type is not supported.",
        ),
      );
    next();
  };
  // Provider webhooks keep their raw body for signature verification (the route parses it itself, after the check).
  const json = express.json({ limit: config.http.bodyLimitBytes, strict: true });
  const skipWebhooks = (middleware) => (req, res, next) =>
    req.path.startsWith(WEBHOOK_PATH_PREFIX) ? next() : middleware(req, res, next);
  return [skipWebhooks(guard), skipWebhooks(json)];
}
