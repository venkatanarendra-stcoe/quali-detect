import { createReadStream } from "node:fs";
import { stat } from "node:fs/promises";
import path from "node:path";

/**
 * The READ side of the generated-report object store (docs/modules/reporting-dashboards/SPEC.md 12 item 5, D-3): the API streams a report
 * to an authenticated caller and nothing else, so this reader has no write, no list and no delete; the worker owns the writes
 * (`apps/workers/src/reporting/export/object-store.js`, which builds the SAME key with the SAME rules). The key is
 * `reports/<tenantId>/<reportId>.<csv|pdf>`: built here from two canonical lower-case UUIDs and a closed list of formats, never from a
 * request, a body or a stored name (the `object_key` column is not even read for the path). A value with a separator, `..`, a leading dot,
 * upper case, an over-long segment or a different format cannot form a key (`TypeError`), so a download can neither traverse the tree nor
 * name another tenant's tree: the tenant segment is the session's, validated by the same function.
 */

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const FORMATS = Object.freeze(["csv", "pdf"]);

/**
 * @param {{ tenantId: string, reportId: string, format: string }} ref
 * @returns {string}
 */
export function reportObjectKey({ tenantId, reportId, format }) {
  if (
    typeof tenantId !== "string" ||
    typeof reportId !== "string" ||
    !UUID.test(tenantId) ||
    !UUID.test(reportId) ||
    !FORMATS.includes(format)
  )
    throw new TypeError("Invalid report reference.");
  return `reports/${tenantId}/${reportId}.${format}`;
}

/**
 * @param {{ root: string }} options absolute directory (the same `ARTIFACT_STORE_ROOT` the worker writes to)
 */
export function createReportObjectReader({ root }) {
  if (typeof root !== "string" || !path.isAbsolute(root))
    throw new TypeError("The report store root must be an absolute path.");
  const base = path.resolve(root);
  const locate = (ref) => {
    const key = reportObjectKey(ref);
    const file = path.join(base, ...key.split("/"));
    if (!file.startsWith(`${base}${path.sep}`)) throw new TypeError("Invalid report reference.");
    return { key, file };
  };
  return Object.freeze({
    kind: "local-fs-reports-reader",
    keyFor: (ref) => locate(ref).key,
    /** Size of the object, or null when it does not exist. @param {{ tenantId: string, reportId: string, format: string }} ref */
    async size(ref) {
      const info = await stat(locate(ref).file).catch(() => null);
      return info?.isFile() ? info.size : null;
    },
    /** @param {{ tenantId: string, reportId: string, format: string }} ref @returns {import("node:stream").Readable} */
    open: (ref) => createReadStream(locate(ref).file),
  });
}
