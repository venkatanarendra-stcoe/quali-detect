import { buildPaginationMeta } from "../lib/query.js";

/**
 * Adds `res.success(data, meta?)`, `res.paginated(items, pagination, meta?)` and `res.code(status)` (chainable status),
 * which send the standard envelope `{ success: true, data, meta: { correlationId, ... } }`. Controllers keep the
 * `reply.success(...)` contract they had under Fastify. Handlers must `return res.success(...)`.
 * @returns {import("express").RequestHandler}
 */
export function envelope() {
  return function envelopeMiddleware(req, res, next) {
    res.code = function code(status) {
      return this.status(status);
    };
    res.success = function success(data, meta = {}) {
      return this.json({ success: true, data, meta: { correlationId: req.id, ...meta } });
    };
    res.paginated = function paginated(items, pagination, meta = {}) {
      return this.success(items, { pagination: buildPaginationMeta(pagination), ...meta });
    };
    next();
  };
}
