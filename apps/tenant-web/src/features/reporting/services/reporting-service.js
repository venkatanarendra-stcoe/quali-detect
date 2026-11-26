import { REPORTING_ROUTE_SCHEMAS, createReportBodySchema } from "@qmentisai/shared";
import { ApiError, api } from "@/lib/api/index.js";
import { createMockReportingService } from "./reporting-mock.js";

const BASE_URL = import.meta.env.VITE_API_BASE_URL || "/api/v1";
const TIMEOUT_MS = 20_000;
const CORRELATION_HEADER = "x-correlation-id";

/** A fresh key per user action; a retry of the SAME action reuses it. */
export const newIdempotencyKey = () => crypto.randomUUID();

/** Route key (`GET /reporting/posture`) to its path (`/reporting/posture`). @param {string} route */
const pathOf = (route) => route.slice(route.indexOf(" ") + 1);

/**
 * In development every response is checked against the FROZEN shared schema of its route; a mismatch is logged (never thrown, so a
 * screen keeps working while the contract is fixed). Production does no extra parsing.
 * @param {string} route @param {unknown} data @param {unknown} meta
 */
function checkContract(route, data, meta) {
  if (!import.meta.env.DEV) return;
  const schemas = REPORTING_ROUTE_SCHEMAS[route];
  if (!schemas) return;
  const dataResult = schemas.data.safeParse(data);
  if (!dataResult.success)
    console.error(
      `[reporting] ${route}: data does not match the shared schema`,
      dataResult.error.issues,
    );
  const metaResult = schemas.meta?.safeParse(meta);
  if (metaResult && !metaResult.success)
    console.error(
      `[reporting] ${route}: meta does not match the shared schema`,
      metaResult.error.issues,
    );
}

/**
 * A read that returns `{ data, meta }`. The shared API client unwraps the envelope to `data` only, but every reporting read needs
 * `meta` (`asOf`, `source`, `stale`, `timeZone`) for its footer, so this one function reads the envelope itself with the same
 * rules as the client: cookie session, correlation id, stable error codes through `ApiError`, a 401 reaches the shared handler.
 * @param {string} route @param {Record<string, string | undefined>} query @param {{ signal?: AbortSignal }} [options]
 * @returns {Promise<{ data: any, meta: any }>}
 */
async function readWithMeta(route, query, { signal } = {}) {
  const correlationId = crypto.randomUUID();
  const params = new URLSearchParams();
  for (const [key, value] of Object.entries(query ?? {}))
    if (value !== undefined && value !== null && value !== "") params.set(key, String(value));
  const controller = new AbortController();
  let timedOut = false;
  const timer = setTimeout(() => {
    timedOut = true;
    controller.abort();
  }, TIMEOUT_MS);
  const onAbort = () => controller.abort(signal?.reason);
  signal?.addEventListener("abort", onAbort, { once: true });
  let response;
  try {
    const text = params.toString();
    response = await fetch(`${BASE_URL}${pathOf(route)}${text ? `?${text}` : ""}`, {
      method: "GET",
      credentials: "include",
      headers: { Accept: "application/json", [CORRELATION_HEADER]: correlationId },
      signal: controller.signal,
    });
  } catch (error) {
    if (timedOut)
      throw new ApiError({
        status: 0,
        code: "TIMEOUT",
        message: "The request timed out.",
        correlationId,
      });
    if (signal?.aborted) throw error;
    throw new ApiError({
      status: 0,
      code: "NETWORK_ERROR",
      message: "Network error.",
      correlationId,
    });
  } finally {
    clearTimeout(timer);
    signal?.removeEventListener("abort", onAbort);
  }
  const echoed = response.headers.get(CORRELATION_HEADER) ?? correlationId;
  let envelope = null;
  try {
    envelope = await response.json();
  } catch {
    envelope = null;
  }
  if (envelope?.success === true && response.ok) {
    checkContract(route, envelope.data, envelope.meta);
    return { data: envelope.data, meta: envelope.meta };
  }
  if (envelope?.success === false && envelope.error) {
    // the shared client owns the "signed out" reaction; a cheap call on it reaches the same handler
    if (response.status === 401) api.get("/me").catch(() => {});
    throw new ApiError({
      status: response.status,
      code: envelope.error.code,
      message: envelope.error.message,
      details: envelope.error.details,
      correlationId: envelope.meta?.correlationId ?? echoed,
    });
  }
  throw new ApiError({
    status: response.status,
    code: "UNEXPECTED_RESPONSE",
    message: "Unexpected response from the server.",
    correlationId: echoed,
  });
}

const reportPath = (id) => `/reporting/reports/${id}`;

/**
 * Reporting API (SPEC 9). The tenant is the session's: no tenant id is ever sent. `reportingApi` is the real implementation;
 * `reportingService` is the in-repo mock instead when `VITE_REPORTING_MOCK=true` (development only).
 */
export const reportingApi = {
  /** @param {string} route a key of `REPORTING_ROUTE_SCHEMAS` */
  read: (route, query, options) => readWithMeta(route, query, options),
  createReport: (body, key) =>
    api.post("/reporting/reports", createReportBodySchema.parse(body), {
      headers: { "Idempotency-Key": key ?? newIdempotencyKey() },
    }),
  listReports: (query, { signal } = {}) => api.get("/reporting/reports", { query, signal }),
  getReport: (id, { signal } = {}) => api.get(reportPath(id), { signal }),
  deleteReport: (id) => api.delete(reportPath(id)),
  /** An authenticated request, never a copyable URL: resolves to `{ blob, fileName }`. */
  downloadReport: (id, { signal } = {}) => api.download(`${reportPath(id)}/download`, { signal }),
};

/** True when the screens run on the in-repo mock instead of the API (`VITE_REPORTING_MOCK=true`; development only). */
export const REPORTING_MOCK_ENABLED =
  import.meta.env.VITE_REPORTING_MOCK === "true" && !import.meta.env.PROD;

/** The service the hooks use. Same function names and shapes on both sides; default (flag unset) is the real API. */
export const reportingService = REPORTING_MOCK_ENABLED
  ? createMockReportingService()
  : reportingApi;
