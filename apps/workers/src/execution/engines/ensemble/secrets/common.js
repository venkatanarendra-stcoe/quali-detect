import { redactLogText } from "@qmentisai/infra";
import { z } from "zod";
import { secretsKey } from "../core/merge-keys.js";
import { cleanText } from "../core/scrub.js";
import { SRC_PREFIX, relativeUnderSrc, text } from "../sast/common.js";
import { SECRET_TITLES, describeSecret } from "./type-class.js";

export { SRC_PREFIX, relativeUnderSrc, text };

/**
 * Pieces shared by the two Secrets adapters (docs/modules/scan-engines/SPEC.md 5.6.4, 5.7, SE-40 to SE-44, 7.2). Pure.
 *
 * A secret finding carries a LOCATION, a type class, a fixed platform title, a severity from the platform table and the tool's rule id. It
 * carries NO value, NO value-derived hash or fingerprint, NO snippet, NO match text and NO tool prose: the real Gitleaks `Match` is only
 * the matched span (redacted, so no line is available) and detect-secrets has no match text at all, so evidence is omitted (SE-42, fail
 * closed). `preview` is never set (the framework would drop it anyway: the value is not known).
 */

/** Findings a Secrets tool may report in one run (the framework cuts a larger output to `partial` / `output_too_large`). */
export const SECRETS_MAX_RECORDS = 50_000;

const LINE = z.number().int().min(1).max(10_000_000);
const COLUMN = z.number().int().min(1).max(1_000_000);
export { COLUMN, LINE };

/** A rule id that can appear in a finding: short, no control character, a conservative alphabet. */
export const RULE_ID = /^[A-Za-z0-9][A-Za-z0-9._-]{0,99}$/;

/** The rule id of a detect-secrets `type` label: lower case, every non-alphanumeric run one `-`. @param {string} label */
export function slugOf(label) {
  const slug = String(label)
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-+|-+$/g, "")
    .slice(0, 80);
  return slug === "" ? "unknown" : slug;
}

/**
 * The common body of a secret candidate.
 * @param {{ toolId: "gitleaks" | "detect-secrets", ruleId: string, ruleName?: string, typeClass: string, path: string, startLine: number, endLine?: number, startColumn?: number, endColumn?: number }} input
 */
export function secretBody({
  toolId,
  ruleId,
  ruleName,
  typeClass,
  path,
  startLine,
  endLine,
  startColumn,
  endColumn,
}) {
  const d = describeSecret(toolId, typeClass);
  const end = endLine !== undefined && endLine > startLine ? endLine : undefined;
  return {
    kind: "secret",
    dedupKey: secretsKey(path, startLine, typeClass),
    title: redactLogText(cleanText(SECRET_TITLES[typeClass])).slice(0, 200),
    rule: {
      id: ruleId,
      ...(ruleName ? { name: redactLogText(cleanText(ruleName)).slice(0, 200) } : {}),
    },
    location: {
      path,
      startLine,
      ...(end !== undefined ? { endLine: end } : {}),
      ...(startColumn !== undefined ? { startColumn } : {}),
      ...(endColumn !== undefined ? { endColumn } : {}),
    },
    mergeHints: { typeClass },
    severity: d.severity,
    severityAssumed: d.severityAssumed,
    confidence: d.confidence,
    confidenceBasis: "tool",
    provenance: [{ ruleId, severityRaw: "", severityScale: "platform_table" }],
  };
}
