import { defineToolAdapter } from "../core/adapter.js";
import {
  cyclonedxRecords,
  mapSbomRecord,
  SBOM_MAX_RECORDS,
  sbomRecordSchema,
} from "./cyclonedx.js";
import { planSbomTool, SBOM_TOOL_LIMITS } from "./plan.js";

/**
 * Syft as an SBOM tool adapter (docs/modules/scan-engines/SPEC.md 5.2, 11.3; IMAGES.md section 2). Sealed command line, verbatim from
 * the spike: `-c /rules/syft.yaml dir:/src -o cyclonedx-json` with the update check disabled and the working directory `/tmp`
 * (so a `.syft.yaml` in the repository is never read). Syft is asked for CycloneDX JSON only (OQ-14).
 * The command line is NOT verified against the installed tool beyond the spike (ENG-L06, ENG-L11).
 */

export const SYFT_ARGV = Object.freeze([
  "-c",
  "/rules/syft.yaml",
  "dir:/src",
  "-o",
  "cyclonedx-json",
]);
export const SYFT_ENV = Object.freeze({ SYFT_CHECK_FOR_APP_UPDATE: "false" });

/** @returns {Readonly<object>} */
export function createSyftAdapter() {
  return defineToolAdapter({
    toolId: "syft",
    scanType: "sbom",
    imageKey: "syft",
    plan: (ctx) =>
      planSbomTool(
        {
          toolId: "syft",
          imageKey: "syft",
          argv: SYFT_ARGV,
          env: SYFT_ENV,
          limits: SBOM_TOOL_LIMITS.syft,
        },
        ctx,
      ),
    parse: (streams, kit) =>
      cyclonedxRecords(kit.parseBoundedJson(streams.stdout, kit.limits), kit),
    recordSchema: sbomRecordSchema,
    map: (record) => mapSbomRecord(record),
    maxRecords: SBOM_MAX_RECORDS,
  });
}
