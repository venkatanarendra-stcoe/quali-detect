import fp from "fastify-plugin";
import { ZodError } from "zod";
import { ERROR_CODES } from "@qmentisai/contracts";
import { AppError, ERROR_HTTP_STATUS, ValidationError } from "../errors/app-error.js";
import { formatZodIssues } from "../lib/validation.js";

/** Builds the standard error envelope. Only code, a safe message and optional safe details leave the process. */
function errorEnvelope(request, code, message, details) {
  return {
    success: false,
    error: { code, message, ...(details ? { details } : {}) },
    meta: { correlationId: request.id },
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
  const status = Number(error?.statusCode);
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

/** Centralized error and not-found handling for the whole application. */
export default fp(
  async function errorHandlerPlugin(app) {
    app.setNotFoundHandler((request, reply) =>
      reply
        .status(ERROR_HTTP_STATUS[ERROR_CODES.RESOURCE_NOT_FOUND])
        .send(
          errorEnvelope(
            request,
            ERROR_CODES.RESOURCE_NOT_FOUND,
            "The requested resource was not found.",
          ),
        ),
    );

    app.setErrorHandler((error, request, reply) => {
      const publicError = toPublicError(error);
      if (publicError.statusCode >= 500)
        request.log.error({ err: error, code: publicError.code }, "Request failed");
      else
        request.log.info(
          { code: publicError.code, statusCode: publicError.statusCode },
          "Request rejected",
        );
      return reply
        .status(publicError.statusCode)
        .send(errorEnvelope(request, publicError.code, publicError.message, publicError.details));
    });
  },
  { name: "error-handler" },
);
