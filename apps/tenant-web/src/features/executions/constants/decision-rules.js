import { FLOOR_RULES, SECRETS_RULES } from "@qmentisai/shared";

/**
 * Fixed frontend wording of the scan-decision vocabulary (docs/modules/scan-decisioning/SCREENS.md 2.3, 2.5). The API sends
 * stable rule ids and codes, never the sentence: every text here is written by us. Unknown ids fall back to a generic safe
 * sentence, so a rule added on the server later can never put server text on the screen.
 */

/** Rule id (`FLOOR_RULES`) to the reason of a REQUIRED scan type. */
export const RULE_REASONS = Object.freeze({
  [FLOOR_RULES.MANIFEST]: "A dependency file changed",
  [FLOOR_RULES.CODE]: "Source code changed",
  [FLOOR_RULES.SECRETS]: "Any change is scanned for secrets",
  [FLOOR_RULES.DIFF_UNAVAILABLE]: "Changed files could not be listed, so everything runs",
  [FLOOR_RULES.FULL_RUN]: "Full scan: every enabled scan type runs",
});
export const RULE_REASON_FALLBACK = "Required by a fixed rule";
/** FL-3 under the wider `strict` Secrets mode (removals count too). */
export const SECRETS_STRICT_REASON = "Any changed file, removals included, is scanned for secrets";

/** Stable codes of a scan type that was enabled but not selected. */
export const NOT_SELECTED_TEXT = Object.freeze({ no_matching_changes: "No matching changes" });
export const NOT_SELECTED_FALLBACK = "Not needed for these changes";

/** `agent.status` to the fallback sentence (SCREENS 2.5). `ok` has no entry: it shows the assistant block. */
export const AGENT_FALLBACK_TEXT = Object.freeze({
  not_configured:
    "The analysis assistant is not configured. The required scans for these changes were selected.",
  nothing_to_add: "The assistant was not needed: every enabled scan type was already required.",
  consent_required:
    "The analysis assistant is turned off for your organization. The required scans for these changes were selected.",
  skipped_fork:
    "The assistant is not used for pull requests from forks. The required scans were selected.",
  timeout: "The assistant did not answer in time. The required scans were selected.",
  error: "The assistant was unavailable. The required scans were selected.",
  invalid_output:
    "The assistant's answer was not usable and was ignored. The required scans were selected.",
  interrupted:
    "The assistant was not asked again after a worker restart. The required scans were selected.",
  cancelled: "The run was cancelled during the analysis.",
});
export const AGENT_FALLBACK_GENERIC =
  "The assistant was not used. The required scans were selected.";
export const AGENT_OK_NO_ADDITIONS = "The assistant reviewed the changes and added no scans.";

/** Decision state to chip text (the icon is chosen in the component). */
export const DECISION_STATE_LABELS = Object.freeze({
  required: "Required",
  added: "Added by assistant",
  not_selected: "Not selected",
  not_enabled: "Not enabled",
});

/** File class and diff status wording of the change summary. `one`/`many` are the noun forms. */
export const CLASS_NOUNS = Object.freeze({
  manifest: ["dependency file", "dependency files"],
  code: ["source file", "source files"],
  config: ["configuration file", "configuration files"],
  docs: ["documentation file", "documentation files"],
  other: ["other", "other"],
});
export const CLASS_ORDER = Object.freeze(["manifest", "code", "config", "docs", "other"]);
export const CLASS_TITLES = Object.freeze({
  manifest: "Dependency files",
  code: "Source files",
  config: "Configuration",
  docs: "Documentation",
  other: "Other",
});
export const STATUS_ORDER = Object.freeze(["added", "modified", "removed", "renamed"]);
export const STATUS_TITLES = Object.freeze({
  added: "Added",
  modified: "Modified",
  removed: "Removed",
  renamed: "Renamed",
});

export { SECRETS_RULES };
