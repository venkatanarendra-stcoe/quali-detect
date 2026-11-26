import { createHash } from "node:crypto";
import { actorFrom } from "../../../lib/http.js";
import { isNotModified } from "../../../lib/conditional.js";

/**
 * Canonical JSON (keys sorted at every depth), so an equal DTO gives an equal tag whatever the order it was built in.
 * @param {unknown} value
 */
function canonicalJson(value) {
  const sort = (v) => {
    if (Array.isArray(v)) return v.map(sort);
    if (v && typeof v === "object")
      return Object.fromEntries(
        Object.keys(v)
          .sort()
          .map((k) => [k, sort(v[k])]),
      );
    return v;
  };
  return JSON.stringify(sort(JSON.parse(JSON.stringify(value ?? null))));
}

/** The weak ETag of a reporting DTO as THIS caller sees it (the `meta` instants are not part of it, so an unchanged answer stays 304). */
const reportEtag = (data) =>
  `W/"rpt-${createHash("sha256").update(canonicalJson(data)).digest("hex").slice(0, 32)}"`;

/**
 * Thin controllers of the reporting read routes (docs/modules/reporting-dashboards/SPEC.md 9). The workspace was loaded and authorized by the
 * route guard; the service takes the tenant from the session, never from the request. Answers carry `Cache-Control: private, no-cache` and a
 * weak ETag over the DTO (a `304` is sent only AFTER authorization, scope and the read).
 * @param {{ reads: ReturnType<typeof import("../services/read.js").createReportingReadService> }} deps
 */
export function createReportingReadController({ reads }) {
  /** @param {keyof typeof reads} name */
  const handler = (name) => async (request, reply) => {
    const { data, meta } = await reads[name](actorFrom(request), request.query);
    const etag = reportEtag(data);
    reply.set("ETag", etag);
    reply.set("Cache-Control", "private, no-cache");
    if (isNotModified(request, etag.slice(2))) return reply.status(304).end();
    return reply.success(data, meta);
  };
  return Object.freeze({
    posture: handler("posture"),
    trends: handler("trends"),
    remediation: handler("remediation"),
    sla: handler("sla"),
    aging: handler("aging"),
    scanActivity: handler("scanActivity"),
    coverage: handler("coverage"),
    sbom: handler("sbom"),
    quality: handler("quality"),
    breakdown: handler("breakdown"),
    topRisk: handler("topRisk"),
    workload: handler("workload"),
    overview: handler("overview"),
  });
}
