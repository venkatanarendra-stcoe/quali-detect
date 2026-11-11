import { pinoHttp } from "pino-http";
import { buildLoggerOptions } from "../lib/logging.js";

/**
 * Request logging (pino-http) on the app logger: one line per response with the correlation id, method, path and
 * status; headers (cookies, authorization) are redacted and the body/query string are never logged. `req.log` is a
 * child logger that carries the correlation id and, after authentication, the user/tenant ids.
 * @param {{ logger: import("pino").Logger, config: any }} deps
 * @returns {import("express").RequestHandler[]}
 */
export function requestLogger({ logger, config }) {
  const http = pinoHttp({
    logger,
    genReqId: (req) => req.id,
    serializers: buildLoggerOptions(config).serializers,
    customLogLevel: (_req, res, error) => (error || res.statusCode >= 500 ? "error" : "info"),
    // The error handler already logs failures with their reason; avoid a second, noisy "request errored" line.
    customErrorMessage: () => "request failed",
    customSuccessMessage: () => "request completed",
  });
  // Every line of the request (including those written later by `req.log`) carries the correlation id.
  const bindCorrelation = (req, _res, next) => {
    req.log = req.log.child({ correlationId: req.id });
    next();
  };
  return [http, bindCorrelation];
}
