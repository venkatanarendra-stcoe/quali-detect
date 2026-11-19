import { z } from "zod";
import { defineToolAdapter } from "../core/adapter.js";
import { canonicalPurl } from "../core/merge-keys.js";
import { inventoryArchive } from "../../sbom/index.js";
import {
  mapSbomRecord,
  SBOM_MAX_PATHS,
  SBOM_MAX_RECORDS,
  relativeLocation,
  sbomRecordSchema,
} from "./cyclonedx.js";

/**
 * The `sbom-lite` adapter (docs/modules/scan-engines/SPEC.md 5.10, OQ-18, part E): the existing in-process SBOM inventory engine
 * (docs/modules/executions/SPEC.md 17.ab) seen as one more tool of the ensemble. The legacy engine itself is UNCHANGED and stays the
 * registered default (`sbom`, `default`); this adapter is the same inventory expressed in the ensemble's terms, so the two can be
 * compared and merged with Syft and Trivy once the rollout flag is on. It runs no process and no container (no image, no sandbox).
 *
 * The inventory emits one item per (component, manifest file). The adapter folds the items of one component into one record with
 * the manifests as occurrences (SE-12 read strictly: a tool reports a component once). The items travel as a JSON document
 * through the same bounded parse kit as a real tool's stdout, so hostile data is handled by one code path.
 */

const itemSchema = z.object({
  path: z.string().max(1100),
  componentPurl: z.string().max(1000),
  data: z.object({ scope: z.string().max(20).optional() }).optional(),
});
const SCOPES = new Set(["prod", "dev", "optional", "peer", "unknown"]);
const SCOPE_RANK = { prod: 3, dev: 2, optional: 1, peer: 1, unknown: 0 };

/**
 * Folds legacy inventory items into records (one per canonical purl, the manifests as occurrences). A malformed item yields `null`.
 * @param {unknown} doc @param {{ ToolOutputError: new (reason: string, detail: string) => Error }} kit
 */
export function sbomLiteRecords(doc, kit) {
  if (!Array.isArray(doc)) throw new kit.ToolOutputError("output_invalid", "items are not a list");
  const folded = new Map();
  const invalid = [];
  for (const raw of doc) {
    const item = itemSchema.safeParse(raw);
    const canonical = item.success ? canonicalPurl(item.data.componentPurl) : null;
    const path = item.success ? relativeLocation(item.data.path) : null;
    if (!item.success || canonical === null || path === null) {
      invalid.push(null);
      continue;
    }
    const scope = SCOPES.has(item.data.data?.scope ?? "") ? item.data.data.scope : "unknown";
    const entry = folded.get(canonical.canonical) ?? {
      purl: canonical.canonical,
      scope,
      paths: new Set(),
    };
    entry.paths.add(path);
    if (SCOPE_RANK[scope] > SCOPE_RANK[entry.scope]) entry.scope = scope;
    folded.set(canonical.canonical, entry);
  }
  const records = [...folded.values()]
    .sort((a, b) => (a.purl < b.purl ? -1 : a.purl > b.purl ? 1 : 0))
    .map((e) => {
      const paths = [...e.paths].sort();
      return {
        purl: e.purl,
        ...(e.scope === "unknown" ? {} : { scope: e.scope }),
        paths: paths.slice(0, SBOM_MAX_PATHS),
        pathCount: paths.length,
      };
    });
  return [...records, ...invalid];
}

/** @returns {Readonly<object>} */
export function createSbomLiteAdapter() {
  return defineToolAdapter({
    toolId: "sbom-lite",
    scanType: "sbom",
    imageKey: null,
    plan: () => ({ toolId: "sbom-lite", inProcess: true }),
    parse: (streams, kit) => sbomLiteRecords(kit.parseBoundedJson(streams.stdout, kit.limits), kit),
    recordSchema: sbomRecordSchema,
    map: (record) => mapSbomRecord(record),
    maxRecords: SBOM_MAX_RECORDS,
  });
}

/**
 * Runs the legacy inventory over an extracted tree and returns it as the "streams" of a tool run. `truncated` and `incomplete`
 * are reported beside the streams (the legacy semantics: a truncated inventory is a usable, incomplete result), so the caller
 * marks the tool `partial` instead of the framework failing it as cut output.
 * @param {string} sourceDir the extracted archive
 * @param {{ signal: AbortSignal, log?: (level: string, message: string) => void, inventory?: typeof inventoryArchive }} hooks
 */
export async function collectSbomLiteStreams(
  sourceDir,
  { signal, log, inventory = inventoryArchive },
) {
  const items = [];
  const result = await inventory(
    { sourceDir },
    { signal, ...(log ? { log } : {}), emit: (item) => items.push(item) },
  );
  return {
    streams: { stdout: Buffer.from(JSON.stringify(items), "utf8"), exitCode: 0, truncated: false },
    truncated: result.truncated,
    incomplete: result.incomplete,
    summary: result.summary,
  };
}
