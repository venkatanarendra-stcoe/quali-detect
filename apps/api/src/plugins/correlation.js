import fp from "fastify-plugin";
import { CORRELATION_HEADER } from "../lib/correlation.js";

/** Echoes the request's correlation id (request.id) on every response. */
export default fp(
  async function correlationPlugin(app) {
    app.addHook("onSend", async (request, reply) => {
      reply.header(CORRELATION_HEADER, request.id);
    });
  },
  { name: "correlation" },
);
