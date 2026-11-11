import fp from "fastify-plugin";
import { buildPaginationMeta } from "../lib/query.js";

/**
 * Adds `reply.success(data, meta?)` and `reply.paginated(items, pagination, meta?)` which send the standard envelope:
 * `{ success: true, data, meta: { correlationId, ... } }`. Handlers must `return reply.success(...)`.
 */
export default fp(
  async function envelopePlugin(app) {
    app.decorateReply("success", function success(data, meta = {}) {
      return this.send({ success: true, data, meta: { correlationId: this.request.id, ...meta } });
    });
    app.decorateReply("paginated", function paginated(items, pagination, meta = {}) {
      return this.success(items, { pagination: buildPaginationMeta(pagination), ...meta });
    });
  },
  { name: "envelope" },
);
