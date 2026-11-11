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
export function globalRateLimit({ config, infra }) {
  const { windowMs, max } = config.http.rateLimit;
  return rateLimit({
    windowMs,
    limit: max,
    standardHeaders: "draft-7",
    legacyHeaders: false,
    skip: (req) => req.path === "/health" || req.path === "/ready",
    store: infra.redis
      ? new RedisStore({
          prefix: "qm:rl:global:",
          sendCommand: (...args) => infra.redis.call(...args),
        })
      : undefined,
    handler: (_req, _res, next) =>
      next(new AppError(ERROR_CODES.RATE_LIMITED, "Too many requests. Try again later.")),
  });
}

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
  return [guard, express.json({ limit: config.http.bodyLimitBytes, strict: true })];
}
