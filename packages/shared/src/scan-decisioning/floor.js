import { matchGlob } from "../pipelines/glob.js";
import { classifyPath } from "./classify.js";
import {
  DEFAULT_SECRETS_RULE,
  DIFF_FILE_STATUSES,
  DIFF_STATUSES,
  FILE_CLASSES,
  FLOOR_RULES,
  FLOOR_SCAN_TYPES,
  NOT_SELECTED_REASONS,
  SAMPLE_PATHS_DEFAULT,
  SAMPLE_PATH_MAX_LENGTH,
  SECRETS_RULES,
  WRITTEN_FILE_STATUSES,
} from "./constants.js";

// C0 and C1 control characters, DEL, and the Unicode line/paragraph separators.
// eslint-disable-next-line no-control-regex
const CONTROL_CHARACTERS = /[\u0000-\u001f\u007f-\u009f\u2028\u2029]/g;

/**
 * A path made safe to store and show: control characters removed, cut at `SAMPLE_PATH_MAX_LENGTH`, then passed through the
 * injected credential-shape redaction. Pure (the redaction is a parameter).
 * @param {unknown} path
 * @param {(text: string) => string} redact
 * @returns {string}
 */
export function sanitizeSamplePath(path, redact) {
  const stripped = String(path ?? "")
    .toWellFormed()
    .replace(CONTROL_CHARACTERS, "");
  const capped =
    stripped.length > SAMPLE_PATH_MAX_LENGTH ? stripped.slice(0, SAMPLE_PATH_MAX_LENGTH) : stripped;
  return String(redact(capped)).slice(0, SAMPLE_PATH_MAX_LENGTH);
}

/**
 * The exclusion predicate of the pipeline snapshot (`exclusions.paths`): a pattern matches the path itself or, as a directory,
 * everything below it. The same dialect and the same two matches as the scan handler's extraction filter.
 * @param {string[]} patterns
 * @returns {(path: string) => boolean}
 */
export function createExclusionPredicate(patterns) {
  const list = Array.isArray(patterns) ? patterns.filter((p) => typeof p === "string") : [];
  return (path) =>
    list.some(
      (pattern) => matchGlob(pattern, path) || matchGlob(`${pattern.replace(/\/+$/, "")}/**`, path),
    );
}

const emptyChanged = () => ({
  total: 0,
  byClass: Object.fromEntries(FILE_CLASSES.map((c) => [c, 0])),
  byStatus: Object.fromEntries(DIFF_FILE_STATUSES.map((s) => [s, 0])),
  additions: 0,
  deletions: 0,
  samples: Object.fromEntries(FILE_CLASSES.map((c) => [c, []])),
});

const count = (value) => (Number.isSafeInteger(value) && value > 0 ? value : 0);

/**
 * The deterministic floor of SPEC 5.3: the scans a run MUST do, from the scan kind, the changed files, the enabled scan types,
 * the Secrets rule and the exclusions. Pure: no model, network, clock or I/O; the credential redaction of the sample paths is
 * injected.
 *
 * Rules: FL-5 a full run (`scanKind` "full") selects every enabled type and needs no diff; FL-4 a diff that is not `complete`
 * (truncated, unavailable, missing, malformed, or any scan kind other than "full" without a complete diff) selects every enabled
 * type; FL-1 any manifest file changed, in any status (a rename counts when its previous or its new path is a manifest), selects
 * `sbom` and `sca`; FL-2 a code file added, modified, renamed, copied or changed selects `sast` (a removal alone does not); FL-3
 * the Secrets rule `any_change` (the only rule, owner decision 2026-11-18) selects `secrets` when at least one file was written
 * (added, modified, renamed or copied; status `removed` and `unchanged` are ignored, so a pure deletion never selects it); FL-6 an empty changed set after exclusions gives an empty
 * floor and `zeroScan`. The floor is ALWAYS a subset of `enabledTypes`, in catalog order.
 * @param {{
 *   scanKind: "full" | "incremental",
 *   diff?: { status?: string, files?: Array<{ path: string, previousPath?: string | null, status: string, additions?: number, deletions?: number }> } | null,
 *   enabledTypes: string[],
 *   secretsRule?: "any_change",
 *   exclusions?: { paths?: string[] } | null,
 *   redact?: (text: string) => string,
 *   samplePaths?: number,
 * }} input `redact` is required to produce sample paths (without it `changed.samples` stays empty: fail-safe)
 * @throws {TypeError} when `secretsRule` is anything but `any_change` (fail fast; there is no wider mode)
 * @returns {{
 *   floor: Array<{ scanType: string, ruleIds: string[] }>,
 *   changed: { total: number, byClass: Record<string, number>, byStatus: Record<string, number>, additions: number, deletions: number, samples: Record<string, string[]> },
 *   notSelected: Array<{ scanType: string, reason: string }>,
 *   zeroScan: boolean,
 * }}
 */
export function computeFloor({
  scanKind,
  diff,
  enabledTypes,
  secretsRule = DEFAULT_SECRETS_RULE,
  exclusions,
  redact,
  samplePaths = SAMPLE_PATHS_DEFAULT,
}) {
  if (secretsRule !== SECRETS_RULES.ANY_CHANGE)
    throw new TypeError("secretsRule must be any_change (the only Secrets rule)");
  const enabled = FLOOR_SCAN_TYPES.filter((type) =>
    Array.isArray(enabledTypes) ? enabledTypes.includes(type) : false,
  );
  /** @type {Map<string, Set<string>>} */
  const selected = new Map();
  const select = (type, ruleId) => {
    if (!enabled.includes(type)) return; // the floor is always inside the enabled types
    if (!selected.has(type)) selected.set(type, new Set());
    selected.get(type).add(ruleId);
  };
  const finish = (changed) => {
    const floor = enabled
      .filter((type) => selected.has(type))
      .map((scanType) => ({ scanType, ruleIds: [...selected.get(scanType)] }));
    return {
      floor,
      changed,
      notSelected: enabled
        .filter((type) => !selected.has(type))
        .map((scanType) => ({ scanType, reason: NOT_SELECTED_REASONS.NO_MATCHING_CHANGES })),
      zeroScan: floor.length === 0,
    };
  };
  const selectAll = (ruleId) => {
    for (const type of enabled) select(type, ruleId);
  };

  // FL-5: a full run needs no diff.
  if (scanKind === "full") {
    selectAll(FLOOR_RULES.FULL_RUN);
    return finish(emptyChanged());
  }
  // FL-4: anything but a complete, well-formed list fails closed to every enabled type.
  if (
    scanKind !== "incremental" ||
    diff?.status !== DIFF_STATUSES.COMPLETE ||
    !Array.isArray(diff.files)
  ) {
    selectAll(FLOOR_RULES.DIFF_UNAVAILABLE);
    return finish(emptyChanged());
  }

  const isExcluded = createExclusionPredicate(exclusions?.paths);
  const files = diff.files.filter((file) => {
    if (typeof file?.path !== "string") return true; // a malformed entry is never silently dropped
    if (!isExcluded(file.path)) return true;
    // a rename is dropped only if BOTH paths are excluded
    const previous = file.previousPath;
    return typeof previous === "string" && previous !== "" ? !isExcluded(previous) : false;
  });

  const changed = emptyChanged();
  const sampleLimit = typeof redact === "function" ? Math.max(0, samplePaths) : 0;
  let manifest = false;
  let code = false;
  let written = false;
  for (const file of files) {
    const status = DIFF_FILE_STATUSES.includes(file?.status) ? file.status : "changed";
    const path = typeof file?.path === "string" ? file.path : "";
    const previous = typeof file?.previousPath === "string" ? file.previousPath : null;
    const fileClass = classifyPath(path);
    const previousClass = previous === null ? null : classifyPath(previous);
    changed.total += 1;
    changed.byClass[fileClass] += 1;
    changed.byStatus[status] += 1;
    changed.additions += count(file?.additions);
    changed.deletions += count(file?.deletions);
    if (changed.samples[fileClass].length < sampleLimit)
      changed.samples[fileClass].push(sanitizeSamplePath(path, redact));
    if (fileClass === "manifest" || previousClass === "manifest") manifest = true;
    if (WRITTEN_FILE_STATUSES.includes(status)) {
      written = true;
      if (fileClass === "code" || previousClass === "code") code = true;
    }
  }

  if (manifest) {
    select("sbom", FLOOR_RULES.MANIFEST);
    select("sca", FLOOR_RULES.MANIFEST);
  }
  if (code) select("sast", FLOOR_RULES.CODE);
  // FL-3: only a written file (never a removal) selects Secrets
  if (written) select("secrets", FLOOR_RULES.SECRETS);
  // FL-6: an empty changed set selects nothing; `finish` reports zeroScan.
  return finish(changed);
}
