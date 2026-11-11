import { CORRELATION_HEADER, resolveCorrelationId } from "../lib/correlation.js";

/**
 * First middleware: assigns `req.id` (the caller's safe x-correlation-id or a new UUID) and echoes it on every response.
 * @returns {import("express").RequestHandler}
 */
export function correlation() {
  return function correlationMiddleware(req, res, next) {
    req.id = resolveCorrelationId(req);
    res.setHeader(CORRELATION_HEADER, req.id);
    next();
  };
}
