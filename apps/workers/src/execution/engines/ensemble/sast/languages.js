import { readdir } from "node:fs/promises";
import path from "node:path";
import { COVERAGE_GAP_NAMES } from "@qmentisai/shared";

/**
 * Language detection and the applicability gate of the SAST scan type (docs/modules/scan-engines/SPEC.md 5.5 SE-7 to SE-9, 5.4 rows
 * 3 and 4, OQ-17, owner decision D-24 (c): the gate lands with the SAST part). SE-7: the language of a file is a pure function of its
 * FILE NAME (the extension), never of its content, never by running `file` or a parser.
 *
 * `SUPPORTED_LANGUAGES` are the languages the platform rule pack and Bandit cover (JavaScript, TypeScript, Python, Go). Every other
 * language of `GAP_LANGUAGES` is a SOURCE language the platform has no SAST rule for: its files are relevant (so a tree of them is a
 * coverage gap, table 5.4 row 4, and never "nothing to scan"), and a gap is named with a fixed platform word (`COVERAGE_GAP_NAMES`),
 * never with a repository-derived string.
 */

/** Language of a file extension (lower case, with the dot). */
export const EXTENSION_LANGUAGE = Object.freeze({
  ".js": "javascript",
  ".jsx": "javascript",
  ".mjs": "javascript",
  ".cjs": "javascript",
  ".ts": "typescript",
  ".tsx": "typescript",
  ".mts": "typescript",
  ".cts": "typescript",
  ".py": "python",
  ".go": "go",
  ".java": "java",
  ".kt": "kotlin",
  ".kts": "kotlin",
  ".c": "c",
  ".h": "c",
  ".cc": "cpp",
  ".cpp": "cpp",
  ".cxx": "cpp",
  ".hpp": "cpp",
  ".hh": "cpp",
  ".hxx": "cpp",
  ".cs": "csharp",
  ".php": "php",
  ".rb": "ruby",
  ".rs": "rust",
  ".swift": "swift",
  ".scala": "scala",
  ".dart": "dart",
  ".ex": "elixir",
  ".exs": "elixir",
  ".hs": "haskell",
  ".lua": "lua",
  ".sh": "shell",
  ".bash": "shell",
});
/** Languages a SAST tool of this platform covers. */
export const SUPPORTED_LANGUAGES = Object.freeze(["javascript", "typescript", "python", "go"]);
/** The languages each tool covers (Opengrep with the platform pack: all four; Bandit: Python). */
export const TOOL_LANGUAGES = Object.freeze({
  opengrep: Object.freeze(["javascript", "typescript", "python", "go"]),
  bandit: Object.freeze(["python"]),
});

/**
 * Vendored and generated directories the SAST tools never scan (owner decision 2026-11-21, SPEC 17.w (5)): a PLATFORM-OWNED, fixed list, never
 * read from the repository, so a repository cannot hide its own code with it beyond these eight names. A directory with one of these names
 * is skipped at ANY depth (Opengrep `--exclude <name>`, Bandit `-x` with a star-slash glob per name, the tree walk and the final finding filter), and a
 * file below one is not a source file for the applicability gate. The SECRETS scan type does NOT use this list (secrets hide in vendored and
 * build output; SPEC 17.w (5)).
 */
export const VENDORED_DIRECTORIES = Object.freeze([
  "node_modules",
  "vendor",
  ".venv",
  "venv",
  "site-packages",
  "dist",
  "build",
  "target",
]);
const VENDORED = new Set(VENDORED_DIRECTORIES);

/**
 * Whether a repository-relative POSIX path lies below a vendored directory (any directory segment, never the final file name).
 * @param {string} relativePath
 */
export function isVendoredPath(relativePath) {
  const parts = String(relativePath).split("/");
  for (let i = 0; i < parts.length - 1; i += 1) if (VENDORED.has(parts[i])) return true;
  return false;
}

/** Limits of the bounded tree walk (a hostile or huge tree never costs unbounded memory or time). */
export const WALK_LIMITS = Object.freeze({
  maxEntries: 1_000_000,
  maxPaths: 200_000,
  maxDepth: 64,
});

/** @param {string} name a file name or path @returns {string | null} the language of its extension, or null */
export function languageOfFile(name) {
  const base = String(name).slice(String(name).lastIndexOf("/") + 1);
  const dot = base.lastIndexOf(".");
  if (dot <= 0) return null; // no extension, or a dot file such as `.js`
  return EXTENSION_LANGUAGE[base.slice(dot).toLowerCase()] ?? null;
}

/**
 * @typedef {object} Inventory
 * @property {Record<string, number>} counts source files per language (every known language, supported or not)
 * @property {Record<string, string[]>} paths relative POSIX paths per language, at most `maxPaths` in all (a file beyond the cap is counted only)
 * @property {boolean} truncated the walk hit an entry, path or depth cap: the inventory is NOT the whole tree
 */

/**
 * The inventory of a list of file paths (pure; the caps are the same as the walk's).
 * @param {Iterable<string>} files relative POSIX paths
 * @param {{ maxPaths?: number }} [options]
 * @returns {Inventory}
 */
export function inventoryOf(files, { maxPaths = WALK_LIMITS.maxPaths } = {}) {
  /** @type {Inventory} */
  const inv = { counts: {}, paths: {}, truncated: false };
  let kept = 0;
  for (const file of files) {
    if (isVendoredPath(file)) continue;
    const language = languageOfFile(file);
    if (language === null) continue;
    inv.counts[language] = (inv.counts[language] ?? 0) + 1;
    if (kept < maxPaths) {
      (inv.paths[language] ??= []).push(file);
      kept += 1;
    } else inv.truncated = true;
  }
  return inv;
}

/**
 * A bounded, non-following walk of an extracted tree: regular files only (a symbolic link, device or FIFO is never followed or
 * listed; the extractor creates none), at most `maxEntries` entries and `maxDepth` levels. A cap that is hit marks the inventory
 * `truncated`, and a truncated inventory is never used to claim "nothing to scan" (see {@link applicability}).
 * @param {string} root absolute directory of the extracted tree
 * @param {{ maxEntries?: number, maxPaths?: number, maxDepth?: number }} [limits]
 * @returns {Promise<Inventory>}
 */
export async function walkSourceTree(root, limits = {}) {
  if (typeof root !== "string" || !path.isAbsolute(root))
    throw new TypeError("the tree root must be an absolute path");
  const cap = { ...WALK_LIMITS, ...limits };
  /** @type {Inventory} */
  const inv = { counts: {}, paths: {}, truncated: false };
  let entries = 0;
  let kept = 0;
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
    list.sort((a, b) => (a.name < b.name ? -1 : a.name > b.name ? 1 : 0));
    for (const entry of list) {
      entries += 1;
      if (entries > cap.maxEntries) {
        inv.truncated = true;
        return sorted(inv);
      }
      const relative = rel === "" ? entry.name : `${rel}/${entry.name}`;
      if (entry.isDirectory()) {
        if (VENDORED.has(entry.name)) continue; // a vendored directory is not walked (SPEC 17.w (5))
        if (depth + 1 > cap.maxDepth) inv.truncated = true;
        else stack.push({ dir: path.join(dir, entry.name), rel: relative, depth: depth + 1 });
      } else if (entry.isFile()) {
        const language = languageOfFile(entry.name);
        if (language === null) continue;
        inv.counts[language] = (inv.counts[language] ?? 0) + 1;
        if (kept < cap.maxPaths) {
          (inv.paths[language] ??= []).push(relative);
          kept += 1;
        } else inv.truncated = true;
      }
    }
  }
  return sorted(inv);
}

/** The inventory with its languages and every list in a fixed order (the walk visits directories depth first), so the same tree always gives the same inventory. @param {Inventory} inv */
function sorted(inv) {
  const byText = (a, b) => (a < b ? -1 : a > b ? 1 : 0);
  /** @type {Inventory} */
  const out = { counts: {}, paths: {}, truncated: inv.truncated };
  for (const language of Object.keys(inv.counts).sort(byText))
    out.counts[language] = inv.counts[language];
  for (const language of Object.keys(inv.paths).sort(byText))
    out.paths[language] = [...inv.paths[language]].sort(byText);
  return out;
}

/**
 * What a SAST task can do with an inventory (SPEC 5.4 rows 3 and 4, 5.5 SE-8, SE-9):
 * - a tool is applicable when the tree has a file of a language it covers; otherwise it is recorded `skipped` / `no_applicable_files`
 *   and is never started;
 * - `relevantFilesExist` is whether the tree has ANY source file of a language the platform knows (supported or a gap): without one
 *   the result is "nothing to scan" (row 3); with files but no applicable tool it is a language gap (row 4);
 * - `gaps` are the known source languages with files and no tool (platform words, sorted).
 * A TRUNCATED inventory proves nothing about absence: every tool is applicable and no gap is claimed, so a huge tree is scanned, never
 * declared empty.
 * @param {Inventory} inventory
 * @returns {{ applicable: Record<string, boolean>, relevantFilesExist: boolean, gaps: string[], languages: Record<string, number> }}
 */
export function applicability(inventory) {
  const counts = inventory.counts;
  const has = (list) => list.some((l) => (counts[l] ?? 0) > 0);
  const applicable = Object.fromEntries(
    Object.entries(TOOL_LANGUAGES).map(([tool, langs]) => [
      tool,
      inventory.truncated ? true : has(langs),
    ]),
  );
  const gaps = Object.keys(counts)
    .filter((l) => !SUPPORTED_LANGUAGES.includes(l) && counts[l] > 0)
    .map((l) => (COVERAGE_GAP_NAMES.includes(l) ? l : "other"))
    .sort();
  return {
    applicable,
    relevantFilesExist: inventory.truncated || Object.values(counts).some((n) => n > 0),
    gaps: inventory.truncated ? [] : [...new Set(gaps)],
    languages: Object.fromEntries(
      SUPPORTED_LANGUAGES.filter((l) => (counts[l] ?? 0) > 0).map((l) => [l, counts[l]]),
    ),
  };
}
