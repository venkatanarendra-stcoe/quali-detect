import pino from "pino";
import { REDACT_PATHS } from "@qmentisai/infra";

export { REDACT_PATHS };

/**
 * Pino options for the API logger. Request logs carry the correlation id (as `correlationId`), method and path
 * only: no headers, no query string, no body. Redaction applies to every line.
 * @param {{ log: { level: string } }} config
 */
export function buildLoggerOptions(config) {
  return {
    level: config.log.level,
    redact: { paths: [...REDACT_PATHS], censor: "[REDACTED]" },
    serializers: {
      req: (request) => ({
        method: request.method,
        path: (request.originalUrl ?? request.url)?.split("?")[0],
        remoteAddress: request.ip ?? request.remoteAddress,
      }),
      res: (response) => ({ statusCode: response.statusCode }),
    },
  };
}

/**
 * Creates the root logger of an app instance.
 * @param {{ log: { level: string } }} config
 * @param {object} [loggerOptions] overrides (for example a destination stream in tools)
 */
export function createLogger(config, loggerOptions) {
  return pino(loggerOptions ?? buildLoggerOptions(config));
}
