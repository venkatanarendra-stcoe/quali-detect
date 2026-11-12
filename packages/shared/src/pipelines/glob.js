import { DEFAULT_BRANCH_TOKEN } from "./constants.js";

/**
 * The glob dialect of SPEC §5.5, used by the worker, the API and the dry-run so preview and production cannot diverge.
 * Case-sensitive; `*` matches any run of characters except `/`; `**` matches any run including `/`; `?` matches one
 * character except `/`; everything else is literal. No brace expansion, no `!` negation, no regular expressions.
 *
 * The matcher is a bounded dynamic program over (pattern tokens x input characters): linear in the input for a bounded
 * pattern, with no regular expression and no backtracking, so a hostile ref name cannot cause super-linear work.
 */

/** Longest input the matcher accepts; anything longer never matches (refs are validated to 255 at the SCM boundary). */
export const MAX_GLOB_INPUT_LENGTH = 512;

const PRINTABLE_ASCII = /^[\x20-\x7e]+$/;

/** @param {string} pattern @returns {Array<{ t: "lit", c: string } | { t: "one" } | { t: "star" } | { t: "globstar" }>} */
function tokenize(pattern) {
  const tokens = [];
  for (let i = 0; i < pattern.length; i += 1) {
    const c = pattern[i];
    if (c === "*") {
      if (pattern[i + 1] === "*") {
        tokens.push({ t: "globstar" });
        while (pattern[i + 1] === "*") i += 1;
      } else tokens.push({ t: "star" });
    } else if (c === "?") tokens.push({ t: "one" });
    else tokens.push({ t: "lit", c });
  }
  return tokens;
}

/**
 * Whether `text` matches `pattern` completely.
 * @param {string} pattern
 * @param {string} text
 * @returns {boolean}
 */
export function matchGlob(pattern, text) {
  if (typeof pattern !== "string" || typeof text !== "string") return false;
  if (text.length > MAX_GLOB_INPUT_LENGTH || pattern.length > MAX_GLOB_INPUT_LENGTH) return false;
  const tokens = tokenize(pattern);
  const n = text.length;
  let prev = new Array(n + 1).fill(false);
  prev[0] = true;
  for (const token of tokens) {
    const next = new Array(n + 1).fill(false);
    if (token.t === "star" || token.t === "globstar") next[0] = prev[0];
    for (let j = 1; j <= n; j += 1) {
      const ch = text[j - 1];
      if (token.t === "lit") next[j] = prev[j - 1] && ch === token.c;
      else if (token.t === "one") next[j] = prev[j - 1] && ch !== "/";
      else if (token.t === "star") next[j] = prev[j] || (next[j - 1] && ch !== "/");
      else next[j] = prev[j] || next[j - 1];
    }
    prev = next;
  }
  return prev[n];
}

/**
 * Resolves the `$default_branch` token. A repository without a known default branch resolves it to null (matches nothing).
 * @param {string} pattern @param {string | null | undefined} defaultBranch
 * @returns {string | null}
 */
export const resolvePattern = (pattern, defaultBranch) =>
  pattern === DEFAULT_BRANCH_TOKEN ? (defaultBranch ?? null) : pattern;

/**
 * Include/exclude evaluation: `exclude` wins over `include`; an empty `include` matches nothing.
 * @param {string} name branch, tag or path
 * @param {{ include?: readonly string[], exclude?: readonly string[] }} lists
 * @param {{ defaultBranch?: string | null }} [options]
 * @returns {{ matched: boolean, reason: "included" | "excluded" | "not_included" }}
 */
export function matchIncludeExclude(
  name,
  { include = [], exclude = [] },
  { defaultBranch = null } = {},
) {
  const hits = (list) =>
    list.some((raw) => {
      const pattern = resolvePattern(raw, defaultBranch);
      return pattern !== null && matchGlob(pattern, name);
    });
  if (hits(exclude)) return { matched: false, reason: "excluded" };
  if (hits(include)) return { matched: true, reason: "included" };
  return { matched: false, reason: "not_included" };
}

/**
 * Validates one pattern against the dialect limits. @param {unknown} pattern @param {number} [maxLength]
 * @returns {string | null} a problem description, or null when valid
 */
export function patternProblem(pattern, maxLength = 200) {
  if (typeof pattern !== "string" || pattern.length === 0) return "A pattern must not be empty.";
  if (pattern.length > maxLength) return `A pattern may have at most ${maxLength} characters.`;
  if (!PRINTABLE_ASCII.test(pattern))
    return "A pattern may contain printable ASCII characters only.";
  return null;
}

/**
 * Syntax check of a git ref name entered by a user (manual runs, schedule `ref`): the name is validated by syntax only,
 * the execution module fails the request when the ref does not exist (SPEC §5.6).
 * @param {unknown} name
 */
export function isValidRefName(name) {
  if (typeof name !== "string" || name.length === 0 || name.length > 255) return false;
  // eslint-disable-next-line no-control-regex
  if (/[\x00-\x20\x7f~^:?*[\\]/.test(name)) return false;
  if (name.startsWith("/") || name.endsWith("/") || name.includes("//")) return false;
  if (name.includes("..") || name.includes("@{") || name === "@") return false;
  if (name.endsWith(".") || name.endsWith(".lock")) return false;
  if (name.split("/").some((part) => part.startsWith(".") || part.endsWith(".lock"))) return false;
  return true;
}
