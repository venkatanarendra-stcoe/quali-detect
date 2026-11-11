import { REDACT_PATHS } from "@qmentisai/infra";

export { REDACT_PATHS };

/**
 * Builds the Pino options passed to Fastify. Request logs carry the correlation id (as `correlationId`), method and path
 * only: no headers, no query string, no body.
 * @param {{ log: { level: string } }} config
 */
export function buildLoggerOptions(config) {
  return {
    level: config.log.level,
    redact: { paths: [...REDACT_PATHS], censor: "[REDACTED]" },
    serializers: {
      req: (request) => ({
        method: request.method,
        path: request.url?.split("?")[0],
        remoteAddress: request.ip,
      }),
      res: (reply) => ({ statusCode: reply.statusCode }),
    },
  };
}
