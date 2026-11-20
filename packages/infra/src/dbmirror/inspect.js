import { ArchiveError } from "../archive/errors.js";
import { walkTarGz } from "../archive/tar.js";
import { checkDeclaredSources, classifyRecord } from "./sources.js";

/**
 * Inspects a downloaded snapshot archive WITHOUT extracting it (docs/modules/scan-engines/SPEC.md 5.12, SE-34, SE-35, SE-45, SE-46,
 * T13). Layout of a mirror bundle (a tar.gz with ONE top-level directory):
 *   `metadata.json`        optional, `{ "sources": ["ghsa", "osv", ...] }` the sources the bundle declares
 *   `records/<name>.json`  OSV-style records, each checked by {@link classifyRecord}
 *   any other file        counted (opaque database files, for example the Trivy bbolt file); NOT inspected record by record
 * The reader is the hardened tar reader of the executions module: caps on entries, per-file size, expanded size and expansion
 * ratio (zip bombs), traversal and absolute paths, links, devices. A snapshot is a HOSTILE input: any skipped entry (unsafe path or
 * link) is a violation, stricter than repository extraction. Nothing in the archive is executed or imported.
 *
 * @typedef {{ maxEntries: number, maxFileBytes: number, maxTotalBytes: number, maxRatio: number, maxDepth: number, maxPathLength: number }} ArchiveCaps
 * @typedef {{
 *   verdict: "ok" | "archive_hostile" | "record_invalid" | "quarantined_source" | "source_not_allowed" | "empty",
 *   files: number, records: number, bySource: Record<string, number>, quarantined: number, notAllowed: number, invalid: number,
 *   declaredSources: Array<{ id: string, licence: string, attributionRequired: boolean, attribution: string | null }>
 * }} SnapshotInspection
 */

/** Default caps of a mirror bundle; the OSV and Trivy bundles are large, so the byte caps are configurable by the caller. */
export const DEFAULT_SNAPSHOT_ARCHIVE_CAPS = Object.freeze({
  maxEntries: 2_000_000,
  maxFileBytes: 512 * 1024 * 1024,
  maxTotalBytes: 8 * 1024 * 1024 * 1024,
  maxRatio: 200,
  maxDepth: 8,
  maxPathLength: 512,
});

const MAX_RECORD_BYTES = 1024 * 1024;
const MAX_METADATA_BYTES = 64 * 1024;

/** Collects at most `limit` bytes of one entry; `over` is set when the entry is larger (the rest is discarded). */
function collector(limit) {
  const chunks = [];
  let size = 0;
  return {
    over: false,
    chunks,
    take(buffer) {
      size += buffer.length;
      if (size > limit) this.over = true;
      else chunks.push(Buffer.from(buffer));
    },
    json() {
      if (this.over) return undefined;
      try {
        return JSON.parse(Buffer.concat(chunks).toString("utf8"));
      } catch {
        return undefined;
      }
    },
  };
}

/**
 * @param {import("node:stream").Readable} source the stored (already hash-verified) archive
 * @param {{ caps?: Partial<ArchiveCaps> }} [options]
 * @returns {Promise<SnapshotInspection>}
 */
export async function inspectSnapshotArchive(source, { caps = {} } = {}) {
  const out = {
    verdict: /** @type {SnapshotInspection["verdict"]} */ ("ok"),
    files: 0,
    records: 0,
    bySource: /** @type {Record<string, number>} */ ({}),
    quarantined: 0,
    notAllowed: 0,
    invalid: 0,
    declaredSources: [],
  };
  let metadata;
  let metadataSeen = false;
  let stats;
  try {
    stats = await walkTarGz(source, {
      limits: { ...DEFAULT_SNAPSHOT_ARCHIVE_CAPS, ...caps },
      onFile({ path: rel, size }) {
        out.files += 1;
        if (rel === "metadata.json") {
          metadataSeen = true;
          const c = collector(MAX_METADATA_BYTES);
          return {
            write: (b) => c.take(b),
            close: () => {
              metadata = c.json();
            },
          };
        }
        if (/^records\/(?:[^/]+\/)*[^/]+\.json$/.test(rel)) {
          if (size > MAX_RECORD_BYTES) {
            out.invalid += 1;
            return null;
          }
          const c = collector(MAX_RECORD_BYTES);
          return {
            write: (b) => c.take(b),
            close: () => {
              out.records += 1;
              const verdict = classifyRecord(c.json());
              if (verdict.allowed)
                out.bySource[verdict.source] = (out.bySource[verdict.source] ?? 0) + 1;
              else if (verdict.quarantined) out.quarantined += 1;
              else if (verdict.reason === "invalid") out.invalid += 1;
              else out.notAllowed += 1;
            },
          };
        }
        return null; // opaque file: counted, not read
      },
    });
  } catch (error) {
    if (error instanceof ArchiveError) return { ...out, verdict: "archive_hostile" };
    throw error;
  }
  if (stats.skippedUnsafe > 0 || stats.skippedLinks > 0 || stats.excluded > 0)
    return { ...out, verdict: "archive_hostile" };
  if (metadataSeen) {
    const declared = checkDeclaredSources(metadata?.sources);
    out.declaredSources = declared.sources;
    if (declared.quarantined.length > 0) out.quarantined += declared.quarantined.length;
    else if (!declared.ok) out.notAllowed += Math.max(declared.notAllowed, 1);
  }
  out.verdict =
    out.files === 0
      ? "empty"
      : out.quarantined > 0
        ? "quarantined_source"
        : out.invalid > 0
          ? "record_invalid"
          : out.notAllowed > 0
            ? "source_not_allowed"
            : "ok";
  return out;
}
