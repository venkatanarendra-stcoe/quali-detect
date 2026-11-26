import { z } from "zod";
import { REPORTING_ROUTE_SCHEMAS } from "@qmentisai/shared";

/**
 * Response schemas of the reporting READ routes, for the OpenAPI document. The DTO and `meta` shapes are the frozen contract of
 * `@qmentisai/shared` (`REPORTING_ROUTE_SCHEMAS`); only the envelope is composed here.
 * @param {string} routeKey a key of `REPORTING_ROUTE_SCHEMAS`, e.g. `GET /reporting/posture`
 */
const envelopeOf = (routeKey) => {
  const { data, meta } = REPORTING_ROUTE_SCHEMAS[routeKey];
  return z.object({ success: z.literal(true), data, meta });
};

export const readResponses = Object.freeze({
  posture: envelopeOf("GET /reporting/posture"),
  trends: envelopeOf("GET /reporting/trends"),
  remediation: envelopeOf("GET /reporting/remediation"),
  sla: envelopeOf("GET /reporting/sla"),
  aging: envelopeOf("GET /reporting/aging"),
  scanActivity: envelopeOf("GET /reporting/scan-activity"),
  coverage: envelopeOf("GET /reporting/coverage"),
  sbom: envelopeOf("GET /reporting/sbom"),
  quality: envelopeOf("GET /reporting/quality"),
  breakdown: envelopeOf("GET /reporting/breakdown"),
  topRisk: envelopeOf("GET /reporting/top-risk"),
  workload: envelopeOf("GET /reporting/workload"),
  overview: envelopeOf("GET /reporting/overview"),
});

/** The request schemas of the same routes (the frozen strict query schemas). */
export const readQueries = Object.freeze(
  Object.fromEntries(
    Object.entries(REPORTING_ROUTE_SCHEMAS)
      .filter(([key]) => key.startsWith("GET /reporting/") && !key.includes("/reports"))
      .map(([key, value]) => [key, /** @type {any} */ (value).query]),
  ),
);
