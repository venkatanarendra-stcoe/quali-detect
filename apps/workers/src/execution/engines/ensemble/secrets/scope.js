import { readdir } from "node:fs/promises";
import path from "node:path";
import { WALK_LIMITS } from "../sast/languages.js";
import { MAX_TARGETS, isSafeTargetPath } from "../sast/scope.js";

/**
 * The tree walk, the applicability gate and the incremental scope of the Secrets scan type (docs/modules/scan-engines/SPEC.md 5.4 rows 3 and 4,
 * 5.5, 5.9 SE-22 to SE-24, SE-27, D-7, 11.3 layer 2, SPEC 17.w (5), 17.x). Pure apart from the bounded walk.
 *
 * **Everything is scanned (owner decision 2026-11-21, SPEC 17.w (5)).** Unlike SAST there is NO vendored-directory list: secrets hide in vendored
 * and build output, so `node_modules`, `vendor`, `dist` and the rest are walked and scanned (the size and noise cost is accepted; `.git` is never
 * extracted, SPEC 11.2). Every file is relevant: a tree with no file is "nothing to scan" (row 3), and there is no language, so no language gap.
 */

/**
 * Tool-control files removed at EXTRACTION (SPEC 11.3 layer 2). Verified on a real run (Gitleaks 8.30.1, 2026-11-21): a `.gitleaksignore` in the
 * root of the scanned tree hid ALL findings and no flag (`-c`, `-i`) prevented it, so the file must never reach the tool. `.gitleaks.toml` and
 * `.secrets.baseline` are not read with the sealed command lines (verified) and are removed as well, so a later tool version cannot start
 * reading them. The match is on the file NAME at any depth.
 */
export const SECRETS_TOOL_CONTROL_FILES = Object.freeze([
  ".gitleaksignore",
  ".gitleaks.toml",
  ".secrets.baseline",
]);

/**
 * The extraction predicate of the Secrets scan type: true for a repository-relative path that must not be extracted.
 * @param {string} relativePath
 */
export function isSecretsToolControlPath(relativePath) {
  const p = String(relativePath);
  const name = p.slice(p.lastIndexOf("/") + 1);
  return SECRETS_TOOL_CONTROL_FILES.includes(name);
}

/** The tools of the Secrets scan type that receive explicit targets in an incremental scan (Gitleaks always scans the whole tree, SPEC 5.9). */
export const TARGETED_TOOLS = Object.freeze(["detect-secrets"]);
/** Every Secrets tool, in tool order. */
export const SECRETS_TOOLS = Object.freeze(["gitleaks", "detect-secrets"]);

/**
 * @typedef {object} FileInventory
 * @property {number} count regular files in the tree (counted past the path cap)
 * @property {string[]} paths relative POSIX paths, sorted, at most `maxPaths`
 * @property {boolean} truncated the walk hit an entry, path or depth cap: the inventory is NOT the whole tree
 */

/**
 * A bounded, non-following walk of an extracted tree listing EVERY regular file (a symbolic link, device or FIFO is never followed or listed; the
 * extractor creates none). A cap that is hit marks the inventory `truncated`, and a truncated inventory is never used to claim "nothing to scan".
 * @param {string} root absolute directory of the extracted tree
 * @param {{ maxEntries?: number, maxPaths?: number, maxDepth?: number }} [limits]
 * @returns {Promise<FileInventory>}
 */
export async function walkAllFiles(root, limits = {}) {
  if (typeof root !== "string" || !path.isAbsolute(root))
    throw new TypeError("the tree root must be an absolute path");
  const cap = { ...WALK_LIMITS, ...limits };
  /** @type {FileInventory} */
  const inv = { count: 0, paths: [], truncated: false };
  let entries = 0;
  /** @type {{ dir: string, rel: string, depth: number }[]} */
  const stack = [{ dir: root, rel: "", depth: 0 }];
  while (stack.length > 0) {
    const { dir, rel, depth } = /** @type {{ dir: string, rel: string, depth: number }} */ (
      stack.pop()
    );
    let list;
    try {
      list = await readdir(dir, { withFileTypes: true });
    } catch {
      inv.truncated = true; // an unreadable directory: the inventory is not complete
      continue;
    }
    for (const entry of list) {
      entries += 1;
      if (entries > cap.maxEntries) {
        inv.truncated = true;
        return finish(inv);
      }
      const relative = rel === "" ? entry.name : `${rel}/${entry.name}`;
      if (entry.isDirectory()) {
        if (depth + 1 > cap.maxDepth) inv.truncated = true;
        else stack.push({ dir: path.join(dir, entry.name), rel: relative, depth: depth + 1 });
      } else if (entry.isFile()) {
        inv.count += 1;
        if (inv.paths.length < cap.maxPaths) inv.paths.push(relative);
        else inv.truncated = true;
      }
    }
  }
  return finish(inv);
}

/** The inventory with its paths in a fixed order (the walk visits directories depth first). @param {FileInventory} inv */
function finish(inv) {
  const byText = (a, b) => (a < b ? -1 : a > b ? 1 : 0);
  return { count: inv.count, paths: [...inv.paths].sort(byText), truncated: inv.truncated };
}

/**
 * The inventory of a list of paths (pure).
 * @param {Iterable<string>} files @param {{ maxPaths?: number }} [options] @returns {FileInventory}
 */
export function fileInventoryOf(files, { maxPaths = WALK_LIMITS.maxPaths } = {}) {
  /** @type {FileInventory} */
  const inv = { count: 0, paths: [], truncated: false };
  for (const file of files) {
    inv.count += 1;
    if (inv.paths.length < maxPaths) inv.paths.push(file);
    else inv.truncated = true;
  }
  return finish(inv);
}

/**
 * @typedef {object} SecretsScopePlan
 * @property {"full" | "targets" | "full_filtered"} kind the scope of the TASK (the widest of the tools)
 * @property {Set<string> | null} changed the changed paths the filter keeps (null for `full`)
 * @property {Record<string, string[] | null>} targets per tool: the sorted target list, or null when the tool scans the whole tree
 * @property {Record<string, "full" | "targets" | "full_filtered">} toolKinds the scope kind each tool ran with (SPEC 7.2 `scope.kind`)
 * @property {number} targetsDropped changed paths that are not in the tree (a deleted or renamed file)
 */

/**
 * Incremental scope (SPEC 5.9): without a COMPLETE changed-path list every tool scans the whole tree and nothing is filtered (fail closed, SE-23).
 * With one, detect-secrets receives the changed files that exist in the tree as explicit targets (at most {@link MAX_TARGETS}, each a valid
 * target); Gitleaks scans the whole tree (`full_filtered`); the SAME filter is applied once to the merged findings (SE-24).
 * @param {{ status: string, paths: string[] } | null | undefined} changedPaths
 * @param {FileInventory} inventory
 * @returns {SecretsScopePlan}
 */
export function planSecretsScope(changedPaths, inventory) {
  if (changedPaths?.status !== "complete" || !Array.isArray(changedPaths.paths))
    return {
      kind: "full",
      changed: null,
      targets: {},
      toolKinds: { gitleaks: "full", "detect-secrets": "full" },
      targetsDropped: 0,
    };
  const changed = new Set(changedPaths.paths.filter((p) => typeof p === "string"));
  const widened = (dropped) => ({
    kind: /** @type {const} */ ("full_filtered"),
    changed,
    targets: {},
    toolKinds: { gitleaks: "full_filtered", "detect-secrets": "full_filtered" },
    targetsDropped: dropped,
  });
  if (inventory.truncated) return widened(0);
  const inTree = new Set(inventory.paths);
  const present = [...changed].filter((p) => inTree.has(p));
  const dropped = changed.size - present.length;
  const list = present.filter(isSafeTargetPath).sort();
  // a changed file of the tree that cannot be a target (an unusual name) is never skipped: the run becomes a full one, then filtered
  if (list.length !== present.length || list.length > MAX_TARGETS) return widened(dropped);
  return {
    kind: "targets",
    changed,
    targets: { gitleaks: null, "detect-secrets": list },
    toolKinds: { gitleaks: "full_filtered", "detect-secrets": "targets" },
    targetsDropped: dropped,
  };
}

/**
 * The inventory restricted to the changed paths (an incremental run decides applicability over the CHANGED files only). A truncated inventory
 * stays truncated (it proves nothing), and a full run (`changed` null) is unchanged.
 * @param {FileInventory} inventory @param {Set<string> | null} changed @returns {FileInventory}
 */
export function scopedFileInventory(inventory, changed) {
  if (changed === null || inventory.truncated) return inventory;
  const paths = inventory.paths.filter((p) => changed.has(p));
  return { count: paths.length, paths, truncated: false };
}

/**
 * What a Secrets task can do with an inventory (SPEC 5.4 row 3, 5.5 SE-8, SE-9): both tools are applicable when the tree has at least one file;
 * otherwise each is recorded `skipped` / `no_applicable_files` and never started, and the result is "nothing to scan". A TRUNCATED inventory
 * proves nothing about absence: both tools are applicable.
 * @param {FileInventory} inventory
 * @returns {{ applicable: Record<string, boolean>, relevantFilesExist: boolean, gaps: string[], files: number }}
 */
export function secretsApplicability(inventory) {
  const any = inventory.truncated || inventory.count > 0;
  return {
    applicable: Object.fromEntries(SECRETS_TOOLS.map((tool) => [tool, any])),
    relevantFilesExist: any,
    gaps: [],
    files: inventory.count,
  };
}
