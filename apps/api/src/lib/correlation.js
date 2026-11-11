import { randomUUID } from "node:crypto";

export const CORRELATION_HEADER = "x-correlation-id";
const SAFE_CORRELATION_ID = /^[A-Za-z0-9._-]{1,128}$/;

/**
 * Returns the caller's x-correlation-id when it is a safe token, otherwise a new UUID.
 * Untrusted input is constrained so it cannot inject log lines or oversized values.
 * @param {{ headers: Record<string, string | string[] | undefined> }} request
 */
export function resolveCorrelationId(request) {
  const incoming = request.headers[CORRELATION_HEADER];
  return typeof incoming === "string" && SAFE_CORRELATION_ID.test(incoming)
    ? incoming
    : randomUUID();
}
