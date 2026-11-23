import { ZodError } from "zod";
import { ApiError } from "@/lib/api/index.js";

/**
 * Parses `value` with a frozen shared schema. A refusal becomes the SAME `ApiError` the server answers
 * (`VALIDATION_FAILED`, 400, `details.reason` from the Zod issue `params.reason` such as `credential_shape` and
 * `details.field`), so a form handles a client refusal and a server refusal in one place.
 * @template T
 * @param {{ parse: (value: unknown) => T }} schema
 * @param {unknown} value
 * @returns {T}
 */
export function parseOrApiError(schema, value) {
  try {
    return schema.parse(value);
  } catch (error) {
    if (!(error instanceof ZodError)) throw error;
    const issue = error.issues[0];
    throw new ApiError({
      status: 400,
      code: "VALIDATION_FAILED",
      message: "The request is not valid.",
      details: {
        reason: issue?.params?.reason ?? issue?.message,
        field: issue?.path?.[0] !== undefined ? String(issue.path[0]) : undefined,
      },
    });
  }
}

/** The form field a `VALIDATION_FAILED` refusal points at, and the stable reason, or null. @param {unknown} error */
export function validationDetails(error) {
  if (!(error instanceof ApiError) || error.code !== "VALIDATION_FAILED") return null;
  return { reason: error.details?.reason ?? null, field: error.details?.field ?? null };
}

/** The `details.reason` of a 409 `FINDING_STATE_CONFLICT`, else null. @param {unknown} error */
export function conflictReason(error) {
  return error instanceof ApiError && error.code === "FINDING_STATE_CONFLICT"
    ? (error.details?.reason ?? "stale_revision")
    : null;
}
