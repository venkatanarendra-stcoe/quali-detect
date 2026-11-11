import { ValidationError } from "../errors/app-error.js";

/**
 * Whether a value is a Zod schema.
 * @param {unknown} value
 */
export function isZodSchema(value) {
  return (
    Boolean(value) &&
    typeof value === "object" &&
    typeof value.safeParse === "function" &&
    "_def" in value
  );
}

/**
 * Converts Zod issues to the safe public shape (path, code, message).
 * @param {import("zod").ZodError} error
 */
export function formatZodIssues(error) {
  return error.issues.map((issue) => ({
    path: issue.path.join("."),
    code: issue.code,
    message: issue.message,
  }));
}

/**
 * Validates `data` against a Zod schema outside of route validation (e.g. inside a service or a message handler).
 * @template T
 * @param {import("zod").ZodType<T>} schema
 * @param {unknown} data
 * @param {string} [source] Label returned in the error (body, querystring, params, message...).
 * @returns {T}
 * @throws {ValidationError}
 */
export function parseWith(schema, data, source = "body") {
  const result = schema.safeParse(data);
  if (!result.success) throw new ValidationError(formatZodIssues(result.error), { source });
  return result.data;
}

const VALIDATED_PARTS = Object.freeze([
  ["params", "params"],
  ["body", "body"],
  ["querystring", "query"],
  ["headers", "headers"],
]);

/** Express 5 exposes `req.query` as a getter only; validated (coerced) values replace it as an own property. */
function replaceRequestPart(req, key, value) {
  Object.defineProperty(req, key, { value, writable: true, configurable: true, enumerable: true });
}

/**
 * Per-route validation middleware. `schema.params | querystring | body | headers` are Zod schemas; the parsed values
 * (coercions, defaults, transforms) replace the raw input, so handlers only ever see validated data. Invalid input
 * becomes a `ValidationError` (400 VALIDATION_FAILED) with the same `source` labels as before the Express migration.
 * It runs after authentication and tenant context (ADR-007 order), so unauthenticated callers never learn the schema.
 * @param {Record<string, unknown>} [schema] the route's `schema` option
 * @returns {import("express").RequestHandler | null} null when the route validates nothing
 */
export function validate(schema = {}) {
  const parts = VALIDATED_PARTS.filter(([part]) => schema[part] !== undefined);
  for (const [part] of parts) {
    if (!isZodSchema(schema[part])) throw new TypeError(`Route ${part} must be a Zod schema.`);
  }
  if (parts.length === 0) return null;
  return function validateRequest(req, _res, next) {
    for (const [part, key] of parts) {
      const result = schema[part].safeParse(req[key]);
      if (!result.success)
        return next(new ValidationError(formatZodIssues(result.error), { source: part }));
      if (key === "headers") continue; // headers stay as received; validation is the check
      replaceRequestPart(req, key, result.data);
    }
    next();
  };
}
