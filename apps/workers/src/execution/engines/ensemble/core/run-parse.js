import { OUTPUT_DROP_RATIO_LIMIT, candidateSchema } from "@qmentisai/shared";
import { PARSE_KIT, PARSE_LIMITS, ToolOutputError } from "./parse-kit.js";
import { lengthBucket, scrubDeep, secretVariants } from "./scrub.js";

/**
 * Runs the parse, validate and map pipeline of ONE tool adapter over ONE tool output (docs/modules/scan-engines/SPEC.md 7.2
 * "Mapper boundaries", SE-4, ENG-S09). Hostile output is contained here, whatever the adapter does:
 * - a tool that exited with an unaccepted code, or whose stdout was cut by the capture cap, is `failed` (`exit_code`, `output_too_large`)
 *   and its output is not trusted;
 * - the records pass the parse kit (size, depth, node and forbidden-key caps), then the adapter's strict Zod record schema; a record
 *   that fails is DROPPED and counted, one that makes the mapper throw is dropped too;
 * - more records than `maxRecords` are cut (`partial`, `output_too_large`); over 20 percent dropped is `failed` `output_invalid`;
 * - the provenance, scan type, task reference and raw reference of a candidate are set HERE from trusted context, never by the
 *   mapper; secret fields are removed from the record before the mapper sees it, and every string is scrubbed of their values.
 * Pure apart from reading the supplied streams; no I/O, no clock.
 */

/**
 * @typedef {object} ParseContext
 * @property {string} taskRef the scan task id (UUID): a candidate belongs to exactly this task
 * @property {string} toolRunId UUID of the tool run (`rawRef.toolRunId`)
 * @property {string} toolVersion
 * @property {string | null} imageDigest `sha256:<64 hex>` of the image, null for the in-process sbom-lite
 * @property {((value: string) => string) | undefined} [fingerprinter] in-task HMAC ({@link createTaskFingerprinter})
 * @property {((relativePath: string) => boolean) | undefined} [pathExists] whether a tool-reported path exists in the extracted tree
 */
/**
 * @typedef {object} ParseOutcome
 * @property {"succeeded" | "partial" | "failed"} status
 * @property {"exit_code" | "output_invalid" | "output_too_large" | null} reason
 * @property {object[]} candidates validated candidates (empty when failed)
 * @property {number} recordsSeen @property {number} recordsDropped @property {number} findingsMapped
 * @property {boolean} truncated @property {Record<string, number>} severityCounts
 */

const failed = (reason, extra = {}) => ({
  status: "failed",
  reason,
  candidates: [],
  recordsSeen: 0,
  recordsDropped: 0,
  findingsMapped: 0,
  truncated: false,
  severityCounts: { critical: 0, high: 0, medium: 0, low: 0, info: 0 },
  ...extra,
});

const BASE_SHORT = /^sha256:([0-9a-f]{64})$/;
const shortDigest = (digest) => {
  const m = typeof digest === "string" ? BASE_SHORT.exec(digest) : null;
  return m ? `sha256:${m[1].slice(0, 8)}` : "none";
};

/**
 * @param {Readonly<any>} adapter a {@link defineToolAdapter} result
 * @param {{ stdout: Buffer | string, exitCode: number | null, truncated?: boolean }} streams
 * @param {ParseContext} ctx
 * @param {Partial<typeof PARSE_LIMITS>} [limits]
 * @returns {ParseOutcome}
 */
export function runToolParse(adapter, streams, ctx, limits = {}) {
  const cap = { ...PARSE_LIMITS, ...limits };
  if (!adapter.acceptedExitCodes.includes(streams.exitCode)) return failed("exit_code");
  if (streams.truncated === true) return failed("output_too_large", { truncated: true });
  let records;
  try {
    records = adapter.parse(streams, { ...PARSE_KIT, limits: cap });
    if (!Array.isArray(records))
      throw new ToolOutputError("output_invalid", "records are not a list");
  } catch (error) {
    return failed(error instanceof ToolOutputError ? error.reason : "output_invalid");
  }
  const maxRecords = Math.min(adapter.maxRecords ?? cap.maxRecords, cap.maxRecords);
  const truncated = records.length > maxRecords;
  const seen = Math.min(records.length, maxRecords);
  const candidates = [];
  const severityCounts = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  let dropped = 0;
  for (let i = 0; i < seen; i += 1) {
    const candidate = oneRecord(adapter, records[i], i, ctx);
    if (candidate === null) {
      dropped += 1;
      continue;
    }
    candidates.push(candidate);
    severityCounts[candidate.severity] += 1;
  }
  if (seen > 0 && dropped / seen > OUTPUT_DROP_RATIO_LIMIT)
    return failed("output_invalid", { recordsSeen: seen, recordsDropped: dropped, truncated });
  const partial = dropped > 0 || truncated;
  return {
    status: partial ? "partial" : "succeeded",
    reason: truncated ? "output_too_large" : dropped > 0 ? "output_invalid" : null,
    candidates,
    recordsSeen: seen,
    recordsDropped: dropped,
    findingsMapped: candidates.length,
    truncated,
    severityCounts,
  };
}

/** @returns {object | null} the validated candidate, or null when the record is dropped */
function oneRecord(adapter, raw, ordinal, ctx) {
  try {
    const parsed = adapter.recordSchema.safeParse(raw);
    if (!parsed.success) return null;
    const record = { ...parsed.data };
    const secrets = [];
    let maxLength = 0;
    let fingerprint;
    for (const field of adapter.secretFields) {
      const value = record[field];
      delete record[field];
      if (value === undefined || value === null || value === "") continue;
      const text = String(value);
      secrets.push(text);
      maxLength = Math.max(maxLength, text.length);
      if (field === adapter.fingerprintField && ctx.fingerprinter)
        fingerprint = ctx.fingerprinter(text);
    }
    const variants = [...new Set(secrets.flatMap((v) => secretVariants(v)))];
    const mapped = adapter.map(record, { toolId: adapter.toolId, scanType: adapter.scanType });
    if (!mapped || typeof mapped !== "object" || Array.isArray(mapped)) return null;
    const provenanceIn = Array.isArray(mapped.provenance) ? mapped.provenance[0] : undefined;
    const rawRef = { toolRunId: ctx.toolRunId, ordinal };
    let candidate = scrubDeep(
      {
        ...mapped,
        schemaVersion: 1,
        scanType: adapter.scanType,
        taskRef: ctx.taskRef,
        rawRef,
        rule: { ...mapped.rule, tool: adapter.toolId },
        provenance: [
          {
            ...provenanceIn,
            toolId: adapter.toolId,
            toolVersion: ctx.toolVersion,
            imageDigestShort: shortDigest(ctx.imageDigest),
            rawRef,
          },
        ],
        confidenceBasis: mapped.confidenceBasis ?? "tool",
      },
      variants,
    );
    if (candidate.kind === "secret") {
      // a preview only for a value longer than 12, at most 4 characters; the bucket is computed here, never by the mapper
      if (maxLength > 12 && typeof candidate.preview === "string")
        candidate.preview = candidate.preview.slice(0, 4);
      else delete candidate.preview;
      if (maxLength > 0) candidate.valueLengthBucket = lengthBucket(maxLength);
      else delete candidate.valueLengthBucket;
    }
    if (fingerprint && candidate.kind === "secret")
      candidate.mergeHints = { ...candidate.mergeHints, fingerprint };
    const checked = candidateSchema.safeParse(candidate);
    if (!checked.success) return null;
    candidate = checked.data;
    const paths = [candidate.location?.path, ...(candidate.locations ?? []).map((l) => l.path)];
    if (ctx.pathExists && paths.some((p) => p !== undefined && !ctx.pathExists(p))) return null;
    return candidate;
  } catch {
    return null; // a mapper that throws on a validated record is a defect: the record is dropped, never the process
  }
}
