/**
 * Pure parsing of the GitHub changed-file answers (docs/modules/scan-decisioning/SPEC.md 5.2 CD-4, CD-5, CD-7, 17.a). No I/O.
 *
 * The compare and pull-request-files answers carry, per file, far more than the decision may keep: the `patch` (diff hunks,
 * which are repository CONTENT), the blob/raw/contents URLs and the blob sha. These functions build NEW objects from the five
 * wanted fields and drop everything else before anything is returned, logged or stored (the `patch` never leaves this file).
 * Every string is untrusted data: validated, length-bounded, control characters stripped. Anything that does not validate is a
 * failed parse (the caller maps it to `unavailable`, which makes the floor "all enabled"): a list is never partially accepted.
 */

/** Documented limits (spike, SPEC 17.a). */
export const CHANGED_FILE_LIMITS = Object.freeze({
  /** The compare answer lists at most 300 files for the whole comparison. */
  compareMaxFiles: 300,
  /** The pull-request files answer holds at most 3000 files. */
  pullMaxFiles: 3000,
  pullPageSize: 100,
  pullMaxPages: 30,
  pathMaxLength: 1024,
});

/** File statuses GitHub documents; an unknown status makes the answer invalid. */
const STATUSES = new Set([
  "added",
  "removed",
  "modified",
  "renamed",
  "copied",
  "changed",
  "unchanged",
]);

// eslint-disable-next-line no-control-regex
const CONTROL_CHARACTERS = /[\u0000-\u001f\u007f-\u009f\u2028\u2029]/g;

/** @param {unknown} value @returns {string | null} the stripped path, or null when it is not an acceptable path */
function cleanPath(value) {
  if (typeof value !== "string" || value.length === 0) return null;
  if (value.length > CHANGED_FILE_LIMITS.pathMaxLength) return null;
  const stripped = value.toWellFormed().replace(CONTROL_CHARACTERS, "");
  return stripped.length === 0 ? null : stripped;
}

const countOf = (value) => (Number.isSafeInteger(value) && value >= 0 ? value : null);

/**
 * One file of a GitHub answer reduced to `{ path, previousPath, status, additions, deletions }`, or null when it is invalid.
 * The `patch`, `blob_url`, `raw_url`, `contents_url`, `sha` and every other key are dropped here.
 * @param {unknown} item
 * @returns {{ path: string, previousPath: string | null, status: string, additions: number, deletions: number } | null}
 */
export function parseChangedFile(item) {
  if (item === null || typeof item !== "object" || Array.isArray(item)) return null;
  const path = cleanPath(item.filename);
  if (path === null) return null;
  const hasPrevious = item.previous_filename !== undefined && item.previous_filename !== null;
  const previousPath = hasPrevious ? cleanPath(item.previous_filename) : null;
  if (hasPrevious && previousPath === null) return null;
  if (typeof item.status !== "string" || !STATUSES.has(item.status)) return null;
  const additions = countOf(item.additions);
  const deletions = countOf(item.deletions);
  if (additions === null || deletions === null) return null;
  return { path, previousPath, status: item.status, additions, deletions };
}

/** @param {unknown} items @returns {Array<NonNullable<ReturnType<typeof parseChangedFile>>> | null} null when any item is invalid */
function parseItems(items) {
  if (!Array.isArray(items)) return null;
  const files = [];
  for (const item of items) {
    const file = parseChangedFile(item);
    if (file === null) return null;
    files.push(file);
  }
  return files;
}

/**
 * The compare answer (`GET /repos/{r}/compare/{base}...{head}`): an object with a `files` array. The list is capped by GitHub at
 * 300 files, so `limit` or more files means truncated (the caller then returns no list).
 * @param {unknown} json
 * @param {number} limit files at or above this count mean truncated (at most `compareMaxFiles`)
 * @returns {{ ok: true, files: ReturnType<typeof parseItems>, truncated: boolean } | { ok: false }}
 */
export function parseCompareResponse(json, limit = CHANGED_FILE_LIMITS.compareMaxFiles) {
  if (json === null || typeof json !== "object" || Array.isArray(json)) return { ok: false };
  const files = parseItems(json.files);
  if (files === null) return { ok: false };
  return {
    ok: true,
    files,
    truncated: files.length >= Math.min(limit, CHANGED_FILE_LIMITS.compareMaxFiles),
  };
}

/**
 * One page of the pull-request files answer: a JSON array of files.
 * @param {unknown} json
 * @returns {{ ok: true, files: ReturnType<typeof parseItems> } | { ok: false }}
 */
export function parsePullFilesPage(json) {
  const files = parseItems(json);
  return files === null ? { ok: false } : { ok: true, files };
}
