import { ZodError } from "zod";
import { ERROR_CODES } from "@qmentisai/contracts";
import { AppError, ERROR_HTTP_STATUS, ValidationError } from "../errors/app-error.js";
import { formatZodIssues } from "../lib/validation.js";

/** Builds the standard error envelope. Only code, a safe message and optional safe details leave the process. */
function errorEnvelope(req, code, message, details) {
  return {
    success: false,
    error: { code, message, ...(details ? { details } : {}) },
    meta: { correlationId: req.id },
  };
}

/**
 * Maps any thrown value to a safe `{ statusCode, code, message, details }`.
 * Unknown errors become INTERNAL_ERROR with a generic message: stack traces, SQL and provider details are logged
 * server-side (with the correlation id) and never returned.
 */
export function toPublicError(error) {
  if (error instanceof AppError)
    return {
      statusCode: error.statusCode,
      code: error.code,
      message: error.message,
      details: error.details,
    };
  if (error instanceof ZodError) {
    const validation = new ValidationError(formatZodIssues(error));
    return {
      statusCode: validation.statusCode,
      code: validation.code,
      message: validation.message,
      details: validation.details,
    };
  }
  const status = Number(error?.statusCode ?? error?.status);
  if (status === 413)
    return {
      statusCode: 413,
      code: ERROR_CODES.PAYLOAD_TOO_LARGE,
      message: "The request body is too large.",
    };
  if (status === 415)
    return {
      statusCode: 415,
      code: ERROR_CODES.UNSUPPORTED_MEDIA_TYPE,
      message: "The request content type is not supported.",
    };
  if (status >= 400 && status < 500)
    return {
      statusCode: status,
      code: ERROR_CODES.BAD_REQUEST,
      message: "The request could not be processed.",
    };
  return {
    statusCode: 500,
    code: ERROR_CODES.INTERNAL_ERROR,
    message: "An unexpected error occurred.",
  };
}

/**
 * JSON 404 for every unmatched route (same envelope as every other error). Mounted after all routers.
 * @returns {import("express").RequestHandler}
 */
export function notFoundHandler() {
  return function notFound(req, res) {
    res
      .status(ERROR_HTTP_STATUS[ERROR_CODES.RESOURCE_NOT_FOUND])
      .json(
        errorEnvelope(req, ERROR_CODES.RESOURCE_NOT_FOUND, "The requested resource was not found."),
      );
  };
}

/**
 * Centralized error middleware (must be last). Maps any thrown value (including body-parser errors) to the stable
 * public error envelope; stacks, SQL and provider details are logged with the correlation id and never returned.
 * @param {{ logger: import("pino").Logger }} deps
 * @returns {import("express").ErrorRequestHandler}
 */
export function errorHandler({ logger }) {
  // Express identifies error middleware by arity: the fourth parameter must stay.
  // eslint-disable-next-line no-unused-vars
  return function handleError(error, req, res, next) {
    const publicError = toPublicError(error);
    const log = req.log ?? logger;
    if (publicError.statusCode >= 500)
      log.error({ err: error, code: publicError.code }, "Request failed");
    else
      log.info({ code: publicError.code, statusCode: publicError.statusCode }, "Request rejected");
    if (res.headersSent) return req.socket.destroy();
    res
      .status(publicError.statusCode)
      .json(errorEnvelope(req, publicError.code, publicError.message, publicError.details));
  };
}
