import {
  CODE_EXTENSIONS,
  CONFIG_EXTENSIONS,
  DOCS_EXTENSIONS,
  MANIFEST_NAMES,
  MANIFEST_PATTERNS,
} from "./constants.js";

const MANIFEST_SET = new Set(MANIFEST_NAMES);
const CODE_SET = new Set(CODE_EXTENSIONS);
const CONFIG_SET = new Set(CONFIG_EXTENSIONS);
const DOCS_SET = new Set(DOCS_EXTENSIONS);

/**
 * The class of a repository path, decided by the path alone (SPEC 5.3, CD-7): no content is read. A manifest is recognised by
 * its base name first; then the extension decides code, configuration or documentation; a remaining dotfile is configuration;
 * everything else (binaries, unknown extensions, no extension) is `other`. Pure.
 * @param {string} path a repository-relative path (untrusted data)
 * @returns {"manifest" | "code" | "config" | "docs" | "other"}
 */
export function classifyPath(path) {
  if (typeof path !== "string" || path === "") return "other";
  const base = path.slice(path.lastIndexOf("/") + 1).toLowerCase();
  if (base === "") return "other";
  if (MANIFEST_SET.has(base) || MANIFEST_PATTERNS.some((pattern) => pattern.test(base)))
    return "manifest";
  const dot = base.lastIndexOf(".");
  if (dot > 0) {
    const extension = base.slice(dot + 1);
    if (CODE_SET.has(extension)) return "code";
    if (CONFIG_SET.has(extension)) return "config";
    if (DOCS_SET.has(extension)) return "docs";
  } else if (dot === 0 && base.length > 1) {
    // a dotfile such as `.env` or `.gitignore`: the "extension" test above skips it (dot at 0), so test `.env` here
    if (CONFIG_SET.has(base.slice(1))) return "config";
  }
  return base.startsWith(".") ? "config" : "other";
}
