import { defineToolAdapter } from "../core/adapter.js";
import {
  cyclonedxRecords,
  mapSbomRecord,
  SBOM_MAX_RECORDS,
  sbomRecordSchema,
  trivyRefPaths,
} from "./cyclonedx.js";
import { planSbomTool, SBOM_TOOL_LIMITS } from "./plan.js";

/**
 * Trivy in SBOM mode as a tool adapter (docs/modules/scan-engines/SPEC.md 5.2, D-3, 11.3; IMAGES.md section 2). Sealed command line,
 * verbatim from the spike: `fs --config /rules/trivy.yaml --scanners license --format cyclonedx /src` (the licence scanner needs
 * no vulnerability database, so no DB mount, and there is no vulnerability scanning in this role). Working directory `/tmp`, so a
 * `trivy.yaml` or `.trivyignore` in the repository is never read. The tree validation of part C rejects a path longer than
 * `PATH_MAX` before this tool runs (Trivy fails fatally on one). The tool id is `trivy`, shared with the SCA role (part G); the
 * registry key is the pair (scan type, tool).
 * The command line is NOT verified against the installed tool beyond the spike (ENG-L06, ENG-L11).
 */

export const TRIVY_SBOM_ARGV = Object.freeze([
  "fs",
  "--config",
  "/rules/trivy.yaml",
  "--scanners",
  "license",
  "--format",
  "cyclonedx",
  "/src",
]);
export const TRIVY_SBOM_ENV = Object.freeze({
  TRIVY_SKIP_VERSION_CHECK: "true",
  TRIVY_DISABLE_TELEMETRY: "true",
  TRIVY_CACHE_DIR: "/tmp/c",
});

/** @returns {Readonly<object>} */
export function createTrivySbomAdapter() {
  return defineToolAdapter({
    toolId: "trivy",
    scanType: "sbom",
    imageKey: "trivy",
    plan: (ctx) =>
      planSbomTool(
        {
          toolId: "trivy",
          imageKey: "trivy",
          argv: TRIVY_SBOM_ARGV,
          env: TRIVY_SBOM_ENV,
          limits: SBOM_TOOL_LIMITS.trivy,
        },
        ctx,
      ),
    parse: (streams, kit) =>
      cyclonedxRecords(kit.parseBoundedJson(streams.stdout, kit.limits), kit, {
        refPaths: trivyRefPaths,
      }),
    recordSchema: sbomRecordSchema,
    map: (record) => mapSbomRecord(record),
    maxRecords: SBOM_MAX_RECORDS,
  });
}
