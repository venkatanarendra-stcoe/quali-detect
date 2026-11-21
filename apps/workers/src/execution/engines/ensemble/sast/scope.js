import { isSafeRelativePath } from "@qmentisai/shared";
import { TOOL_LANGUAGES, languageOfFile } from "./languages.js";

/**
 * Incremental scope of the SAST tools (docs/modules/scan-engines/SPEC.md 5.9 SE-22 to SE-24, SE-27, D-7). The changed-path list of the
 * decision is read by the scan handler (`readChangedPaths`, fail closed to full). What REAL tool output settled (Opengrep 2.0.0 and
 * Bandit 1.9.4, 2026-11-21): both take explicit file targets after `--` (Opengrep `scan <flags> -- /src/a.js ...`, Bandit
 * `<flags> -- /src/a.py ...`, without `-r`), report the same paths in the same form, and answer a target that does not exist with an
 * error (Opengrep exit 2 and no result at all), so every target is validated against the extracted tree BEFORE the run.
 *
 * - `full`: no changed-path list (a full scan, or a list that is truncated, unavailable or not recorded: fail closed, SE-23). Every
 *   tool scans the whole tree and nothing is filtered.
 * - `targets`: an incremental scan with a complete list of at most {@link MAX_TARGETS} changed files of languages the tool covers
 *   that exist in the tree; the tool receives them as explicit targets.
 * - `full_filtered`: an incremental scan whose targets cannot all be given (more than {@link MAX_TARGETS}, a changed file with a name
 *   that is not a valid target, or an inventory that is not the whole tree): the tool runs over the whole tree and the filter keeps the changed paths (SE-24: merge first, filter after).
 * In the two incremental kinds the SAME filter is applied once to every merged finding, so a result never depends on how a tool was
 * scoped. A finding outside the changed paths is dropped from the stored result and counted.
 */

/** Explicit targets of one tool (SPEC 5.9: at most 2000). Above it the run is full and filtered. */
export const MAX_TARGETS = 2000;

// bidirectional, zero-width and line-separator characters (the sandbox refuses them in a path; they are listed here by code point)
const INVISIBLE_PATH = new RegExp(
  `[${["200b-200f", "2028-202e", "2060-2069", "feff"]
    .map((r) =>
      r
        .split("-")
        .map((h) => `\\u${h}`)
        .join("-"),
    )
    .join("")}]`,
  "u",
);

/**
 * SE-27: starts with a letter, digit, `_` or `.` (never `-`), is a safe relative path (no `..`, no control character) without a
 * bidirectional or zero-width character, and is at most 1024 characters.
 */
export function isSafeTargetPath(value) {
  return (
    typeof value === "string" &&
    value.length <= 1024 &&
    /^[\p{L}\p{N}_.]/u.test(value) &&
    !INVISIBLE_PATH.test(value) &&
    isSafeRelativePath(value)
  );
}

/**
 * @typedef {object} ScopePlan
 * @property {"full" | "targets" | "full_filtered"} kind
 * @property {Set<string> | null} changed the changed paths the filter keeps (null for `full`)
 * @property {Record<string, string[] | null>} targets per tool: the sorted target list, or null when the tool scans the whole tree
 * @property {number} targetsDropped changed paths of a tool's languages that are not in the tree (a deleted or renamed file)
 */

/**
 * @param {{ status: string, paths: string[] } | null | undefined} changedPaths the artifact read by the handler
 * @param {import("./languages.js").Inventory} inventory
 * @returns {ScopePlan}
 */
export function planScope(changedPaths, inventory) {
  const none = { kind: "full", changed: null, targets: {}, targetsDropped: 0 };
  if (changedPaths?.status !== "complete" || !Array.isArray(changedPaths.paths))
    return /** @type {ScopePlan} */ (none);
  const changed = new Set(changedPaths.paths.filter((p) => typeof p === "string"));
  if (inventory.truncated)
    return { kind: "full_filtered", changed, targets: {}, targetsDropped: 0 };
  /** @type {Record<string, string[] | null>} */
  const targets = {};
  let widen = false;
  let dropped = 0;
  for (const [tool, languages] of Object.entries(TOOL_LANGUAGES)) {
    const inTree = new Set(languages.flatMap((l) => inventory.paths[l] ?? []));
    const present = [...changed].filter((p) => inTree.has(p));
    const list = present.filter(isSafeTargetPath).sort();
    // a changed file of the tree that cannot be a target (an unusual name) is never skipped: the run becomes a full one, then filtered
    if (list.length !== present.length || list.length > MAX_TARGETS) widen = true;
    dropped += [...changed].filter(
      (p) => languages.includes(languageOfFile(p) ?? "") && !inTree.has(p),
    ).length;
    targets[tool] = list;
  }
  if (widen) return { kind: "full_filtered", changed, targets: {}, targetsDropped: dropped };
  return { kind: "targets", changed, targets, targetsDropped: dropped };
}

/**
 * The one filter of SE-24, applied to the MERGED findings. Findings with no path are kept (SAST findings always have one).
 * @param {object[]} findings @param {Set<string> | null} changed
 * @returns {{ kept: object[], dropped: number }}
 */
export function filterToChanged(findings, changed) {
  if (changed === null) return { kept: findings, dropped: 0 };
  const kept = findings.filter((f) => {
    const p = f.location?.path;
    return p === undefined || changed.has(p);
  });
  return { kept, dropped: findings.length - kept.length };
}

/**
 * The inventory restricted to the changed paths (an incremental run decides applicability and gaps over the CHANGED files only). A
 * truncated inventory stays truncated (it proves nothing), and a full run (`changed` null) is unchanged.
 * @param {import("./languages.js").Inventory} inventory @param {Set<string> | null} changed
 * @returns {import("./languages.js").Inventory}
 */
export function scopedInventory(inventory, changed) {
  if (changed === null || inventory.truncated) return inventory;
  /** @type {import("./languages.js").Inventory} */
  const out = { counts: {}, paths: {}, truncated: false };
  for (const [language, list] of Object.entries(inventory.paths)) {
    const inScope = list.filter((p) => changed.has(p));
    if (inScope.length === 0) continue;
    out.paths[language] = inScope;
    out.counts[language] = inScope.length;
  }
  return out;
}
