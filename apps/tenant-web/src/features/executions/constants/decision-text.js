import {
  CLASS_NOUNS,
  CLASS_ORDER,
  NOT_SELECTED_FALLBACK,
  NOT_SELECTED_TEXT,
  RULE_REASONS,
  RULE_REASON_FALLBACK,
} from "./decision-rules.js";

/**
 * Pure builders of the "Analysis and decision" texts (docs/modules/scan-decisioning/SCREENS.md 2). No React. Everything that
 * comes from the model or from repository paths goes through `inertText` before it reaches the screen.
 */

const SCAN_LABELS = Object.freeze({ sbom: "SBOM", sca: "SCA", sast: "SAST", secrets: "Secrets" });
const SHOWN = new Set(["required", "added"]);

// C0/C1 controls, DEL, zero-width and bidirectional formatting characters, line/paragraph separators, BOM.
// eslint-disable-next-line no-control-regex
const HOSTILE = /[\x00-\x1f\x7f-\x9f\u200b-\u200f\u2028-\u202e\u2060-\u2069\ufeff]+/g;

/**
 * Makes an untrusted string safe to show as plain text: non-strings become "", control, zero-width and bidirectional
 * characters become one space, whitespace is collapsed, and the length is capped (with an ellipsis). React escapes the
 * result as text; this function only removes what could disguise or break the layout. It never interprets markup.
 * @param {unknown} value
 * @param {number} [max] maximum length in UTF-16 units
 * @returns {string}
 */
export function inertText(value, max = 1000) {
  if (typeof value !== "string") return "";
  const clean = value.replace(HOSTILE, " ").replace(/\s+/g, " ").trim();
  return clean.length > max ? `${clean.slice(0, max - 1)}…` : clean;
}

/** Reason sentence of a REQUIRED scan type from its rule ids (fixed map; unknown ids give the generic sentence). */
export function requiredReasonText(ruleIds) {
  const ids = Array.isArray(ruleIds) ? ruleIds : [];
  const texts = ids.map((id) => RULE_REASONS[id] ?? RULE_REASON_FALLBACK);
  const unique = [...new Set(texts)];
  return unique.length ? unique.join("; ") : RULE_REASON_FALLBACK;
}

/** Reason sentence of a NOT SELECTED scan type from its stable code. */
export const notSelectedReasonText = (code) => NOT_SELECTED_TEXT[code] ?? NOT_SELECTED_FALLBACK;

const plural = (n, one, many) => `${n} ${n === 1 ? one : many}`;
const count = (n) => (Number.isFinite(n) && n >= 0 ? Math.floor(n) : 0);

/** The scan types the decision ended with (required plus added), in the order the API sends them. */
export const finalTypes = (decision) =>
  (decision?.scanTypes ?? []).filter((t) => SHOWN.has(t.state)).map((t) => t.scanType);
/** The scan types the pipeline had enabled. */
export const enabledTypes = (decision) =>
  (decision?.scanTypes ?? []).filter((t) => t.state !== "not_enabled").map((t) => t.scanType);

/** "SBOM, SCA and Secrets scans" (or "no scans"). */
export function scanTypesInWords(types) {
  const names = types.map((t) => SCAN_LABELS[t] ?? "Unknown");
  if (!names.length) return "no scans";
  const list =
    names.length === 1 ? names[0] : `${names.slice(0, -1).join(", ")} and ${names.at(-1)}`;
  return `${list} ${names.length === 1 ? "scan" : "scans"}`;
}

/** "3 dependency files, 7 source files, 2 other" (zero classes are left out). */
export function classBreakdown(byClass) {
  return CLASS_ORDER.filter((c) => count(byClass?.[c]) > 0)
    .map(
      (c) =>
        `${count(byClass[c])} ${count(byClass[c]) === 1 ? CLASS_NOUNS[c][0] : CLASS_NOUNS[c][1]}`,
    )
    .join(", ");
}

/**
 * The one-sentence summary (SCREENS 2.1), built from counts and codes only, never from model text.
 * @returns {{ text: string, incomplete: boolean }} `incomplete` marks the fail-closed case (shown with an icon)
 */
export function summaryLine(decision) {
  const final = finalTypes(decision).length;
  const enabled = enabledTypes(decision).length;
  if (final === 0) return { text: "No scan applied to these changes.", incomplete: false };
  if (decision.scanKind === "full")
    return { text: "Full scan: every enabled scan type was selected.", incomplete: false };
  const status = decision.diff?.status;
  if (status !== "complete")
    return {
      text: "Incremental scan: the list of changed files could not be read completely, so every enabled scan type was selected.",
      incomplete: true,
    };
  const total = count(decision.diff.changedTotal);
  const breakdown = classBreakdown(decision.diff.summary?.byClass);
  return {
    text: `Incremental scan: ${plural(total, "file", "files")} changed${breakdown ? ` (${breakdown})` : ""}. ${final} of ${enabled} enabled scan types ${final === 1 ? "was" : "were"} selected.`,
    incomplete: false,
  };
}

/** "412 in / 96 out tokens · 3.1 s", or null when no call was made. */
export function usageLine(agent) {
  const u = agent?.usage;
  if (!agent?.provider || !u) return null;
  const parts = [`${count(u.inputTokens)} in / ${count(u.outputTokens)} out tokens`];
  if (count(u.latencyMs) > 0) parts.push(`${(count(u.latencyMs) / 1000).toFixed(1)} s`);
  return parts.join(" · ");
}

/** "anthropic · model-name" (inert text), or null. */
export function providerLine(agent) {
  const provider = inertText(agent?.provider, 80);
  const model = inertText(agent?.model, 120);
  const line = [provider, model].filter(Boolean).join(" · ");
  return line || null;
}

/** The "Analysis completed" row of the Events tab, with the final scan types in words. */
export function analysisCompletedLabel(decision) {
  return decision
    ? `Analysis completed: ${scanTypesInWords(finalTypes(decision))}`
    : "Analysis completed";
}

/** Whether the paths of the change summary were cut (some class shows fewer paths than it counts). */
export function samplesTruncated(summary) {
  return CLASS_ORDER.some(
    (c) => count(summary?.byClass?.[c]) > (summary?.samples?.[c]?.length ?? 0),
  );
}
