import { redactLogText } from "@qmentisai/infra";
import { isSafeRelativePath } from "@qmentisai/shared";
import { z } from "zod";
import { PARSE_LIMITS, parseBoundedJson } from "./engines/ensemble/core/parse-kit.js";

/**
 * The changed-paths artifact (docs/modules/scan-engines/SPEC.md 5.9 SE-22 to SE-24, owner decision D-7). The orchestrator writes it
 * in the decision step of an INCREMENTAL execution (only while the ensemble flag is on); the scan handler reads it back by tenant and
 * execution. This module is the whole contract: the document shape, the caps, the status words and both directions.
 *
 * Fail closed to full (SE-23): the status is `complete` only for a whole, validated list; a truncated or unavailable diff, a list
 * above the caps, a path that is not a safe repository-relative path, a write that failed, an unreadable or malformed document all
 * give a status other than `complete` and NO list, so every tool then scans the whole tree. A partly known scope is never used.
 * Nothing here decides which tool scans what: that (path-form dependent) narrowing is HELD until ENG-L20 (SPEC 17.i).
 */

export const CHANGED_PATHS_NAME = "changed-paths.json";
export const CHANGED_PATHS_SCHEMA_VERSION = 1;
/** At most this many paths (SPEC 5.9 SE-22) and this many bytes (512 KiB) are stored. */
export const CHANGED_PATHS_MAX = 3000;
export const CHANGED_PATHS_MAX_BYTES = 512 * 1024;
export const CHANGED_PATHS_STATUSES = Object.freeze(["complete", "truncated", "unavailable"]);

const documentSchema = z
  .object({
    schemaVersion: z.literal(CHANGED_PATHS_SCHEMA_VERSION),
    total: z.number().int().min(0).max(CHANGED_PATHS_MAX),
    paths: z.array(z.string().min(1).max(1024).refine(isSafeRelativePath)).max(CHANGED_PATHS_MAX),
  })
  .strict()
  .refine((d) => d.total === d.paths.length, "total must equal the number of paths");

/**
 * The document and status for one decision. `files` are the validated entries of change detection (`path`, `previousPath`).
 * @param {{ diffStatus: string, files: Array<{ path?: unknown, previousPath?: unknown }> }} input
 * @returns {{ status: null } | { status: "truncated" | "unavailable", document: null } | { status: "complete", document: { schemaVersion: 1, total: number, paths: string[] } }}
 * `status: null` for a full run (no diff, nothing recorded)
 */
export function buildChangedPaths({ diffStatus, files }) {
  if (diffStatus === "not_needed") return { status: null };
  if (diffStatus === "truncated") return { status: "truncated", document: null };
  if (diffStatus !== "complete" || !Array.isArray(files))
    return { status: "unavailable", document: null };
  const paths = new Set();
  for (const f of files) {
    for (const raw of [f?.path, f?.previousPath]) {
      if (raw === null || raw === undefined) continue;
      const path = typeof raw === "string" ? redactLogText(raw) : null;
      // a path that is not a safe relative path cannot be trusted as a scope: fail closed, not "drop and continue"
      if (path === null || !isSafeRelativePath(path))
        return { status: "truncated", document: null };
      paths.add(path);
      if (paths.size > CHANGED_PATHS_MAX) return { status: "truncated", document: null };
    }
  }
  const document = {
    schemaVersion: CHANGED_PATHS_SCHEMA_VERSION,
    total: paths.size,
    paths: [...paths].sort(),
  };
  if (Buffer.byteLength(JSON.stringify(document)) > CHANGED_PATHS_MAX_BYTES)
    return { status: "truncated", document: null };
  return { status: "complete", document };
}

/**
 * Writes the artifact (insert once; an existing one is kept) and returns what the decision records. A failed write is
 * `unavailable`, never an exception: the scan then runs over the whole tree.
 * @param {{ artifacts: any, tenantId: string, executionId: string, built: ReturnType<typeof buildChangedPaths> }} input
 * @returns {Promise<{ ref: string | null, status: "complete" | "truncated" | "unavailable" | null }>}
 */
export async function writeChangedPaths({ artifacts, tenantId, executionId, built }) {
  if (built.status === null) return { ref: null, status: null };
  if (built.status !== "complete") return { ref: null, status: built.status };
  try {
    await artifacts.put(
      { tenantId, executionId, name: CHANGED_PATHS_NAME },
      Buffer.from(JSON.stringify(built.document), "utf8"),
      { ifAbsent: true, mediaType: "application/json", maxBytes: CHANGED_PATHS_MAX_BYTES },
    );
    return { ref: CHANGED_PATHS_NAME, status: "complete" };
  } catch {
    return { ref: null, status: "unavailable" };
  }
}

/**
 * Reads the artifact the decision names. Scoped by the TRUSTED tenant and execution of the running task (never by a message or by the
 * ref alone: only the fixed artifact name is accepted).
 * @param {{ artifacts: any, tenantId: string, executionId: string, decision: { changedPathsRef?: string | null, changedPathsStatus?: string | null } | null }} input
 * @returns {Promise<{ status: "complete" | "truncated" | "unavailable" | "not_recorded", paths: string[] }>}
 */
export async function readChangedPaths({ artifacts, tenantId, executionId, decision }) {
  const status = decision?.changedPathsStatus;
  if (status === undefined || status === null) return { status: "not_recorded", paths: [] };
  if (status !== "complete")
    return { status: status === "truncated" ? "truncated" : "unavailable", paths: [] };
  if (decision.changedPathsRef !== CHANGED_PATHS_NAME || !artifacts)
    return { status: "unavailable", paths: [] };
  try {
    const stream = artifacts.open({ tenantId, executionId, name: CHANGED_PATHS_NAME });
    const chunks = [];
    let bytes = 0;
    for await (const chunk of stream) {
      bytes += chunk.length;
      if (bytes > CHANGED_PATHS_MAX_BYTES) return { status: "unavailable", paths: [] };
      chunks.push(chunk);
    }
    const doc = documentSchema.parse(
      parseBoundedJson(Buffer.concat(chunks), {
        ...PARSE_LIMITS,
        maxBytes: CHANGED_PATHS_MAX_BYTES,
      }),
    );
    return { status: "complete", paths: doc.paths };
  } catch {
    return { status: "unavailable", paths: [] };
  }
}
