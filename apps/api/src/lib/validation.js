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

/**
 * Fastify validator compiler: route `schema.params | querystring | body | headers` are Zod schemas. Parsed values
 * (coercions, defaults, transforms) replace the raw input, so handlers always receive validated data.
 * Invalid input becomes a `ValidationError` handled by the central error handler.
 * @type {import("fastify").FastifySchemaCompiler<unknown>}
 */
export const zodValidatorCompiler = ({ schema, httpPart }) => {
  if (!isZodSchema(schema)) {
    throw new TypeError(`Route ${httpPart ?? "schema"} must be a Zod schema.`);
  }
  return (data) => {
    const result = schema.safeParse(data);
    return result.success
      ? { value: result.data }
      : { error: new ValidationError(formatZodIssues(result.error), { source: httpPart }) };
  };
};

/**
 * Fastify serializer compiler: response schemas are documentation (OpenAPI); bodies are serialized as JSON.
 * @type {import("fastify").FastifySerializerCompiler<unknown>}
 */
export const zodSerializerCompiler = () => (data) => JSON.stringify(data);
