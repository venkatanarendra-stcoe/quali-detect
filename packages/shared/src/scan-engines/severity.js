import { CONFIDENCE_RANK, CONFIDENCES, SEVERITIES, SEVERITY_RANK } from "./constants.js";
import { cvss3BaseScore } from "./cvss.js";

/**
 * Severity and confidence normalization (docs/modules/scan-engines/SPEC.md 5.7, owner decision D-5). Pure. The POLICY is Confirmed:
 * an unknown or unmappable value becomes `medium` with `assumed: true` (the "severity unmapped" flag); a merged finding takes the
 * HIGHEST severity of its tools. The TABLES are Recommended and can change without a security-suite change (ADR-008 area 18 keeps
 * severity tables out of scope), but the policy properties are asserted.
 */

/** @typedef {"critical" | "high" | "medium" | "low" | "info"} Severity */
/** @typedef {{ severity: Severity, assumed: boolean }} NormalizedSeverity */

const UNMAPPED = Object.freeze({ severity: "medium", assumed: true });
const norm = (raw) => (typeof raw === "string" ? raw.trim().toUpperCase() : "");
const table = (entries) => new Map(Object.entries(entries));

const TRIVY = table({ CRITICAL: "critical", HIGH: "high", MEDIUM: "medium", LOW: "low" });
const OSV = table({
  CRITICAL: "critical",
  HIGH: "high",
  MODERATE: "medium",
  MEDIUM: "medium",
  LOW: "low",
});
const OPENGREP = table({ ERROR: "high", WARNING: "medium", INFO: "low" });
const LEVEL3 = table({ HIGH: "high", MEDIUM: "medium", LOW: "low" });

/** CVSS qualitative bands (v3.x; the v4 scale uses the same bands). A score outside 0 to 10 or a non-number is unmapped. */
export function severityFromCvssScore(score) {
  if (typeof score !== "number" || !Number.isFinite(score) || score < 0 || score > 10)
    return UNMAPPED;
  if (score >= 9) return { severity: "critical", assumed: false };
  if (score >= 7) return { severity: "high", assumed: false };
  if (score >= 4) return { severity: "medium", assumed: false };
  if (score > 0) return { severity: "low", assumed: false };
  return { severity: "info", assumed: false };
}

/**
 * Maps a tool's raw severity to the normalized scale.
 * @param {"cvss" | "trivy" | "osv" | "opengrep" | "bandit" | "gosec" | "none"} scale
 * @param {unknown} raw the tool's value (a string, or a number for `cvss`)
 * @param {{ qmSeverity?: unknown }} [options] `qmSeverity`: a platform SAST rule may set the severity itself (`metadata.qm_severity`)
 * @returns {NormalizedSeverity}
 */
export function normalizeSeverity(scale, raw, options = {}) {
  if (scale === "none") return { severity: "info", assumed: false };
  if (scale === "cvss") return severityFromCvssScore(raw);
  if (scale === "opengrep" && typeof options.qmSeverity === "string") {
    const own = options.qmSeverity.trim().toLowerCase();
    if (SEVERITIES.includes(own))
      return { severity: /** @type {Severity} */ (own), assumed: false };
  }
  const maps = { trivy: TRIVY, osv: OSV, opengrep: OPENGREP, bandit: LEVEL3, gosec: LEVEL3 };
  const map = maps[/** @type {keyof typeof maps} */ (scale)];
  const mapped = map?.get(norm(raw));
  return mapped ? { severity: /** @type {Severity} */ (mapped), assumed: false } : { ...UNMAPPED };
}

/** Entries of an OSV group examined at most (the record schema caps them as well). */
const MAX_OSV_ENTRIES = 40;

/**
 * The severity of an OSV group (SPEC 5.7 "OSV record", owner decision D-5): per advisory a `database_specific.severity` label first
 * (GHSA: CRITICAL, HIGH, MODERATE, LOW), else the CVSS v3.x vector scored by the in-repo calculator ({@link cvss3BaseScore}); the group takes the
 * HIGHEST of its advisories. An advisory with neither (a Go advisory, a CVSS v4 vector only, a v2 vector, a malformed vector) does not
 * count; when NO advisory resolves the result is `medium` with `assumed: true` (the "severity unmapped" flag). Pure.
 * @param {{ label?: unknown, vectors?: unknown[] }[]} entries
 * @returns {{ severity: Severity, assumed: boolean, raw: string, scale: "osv" | "cvss", scores: Record<string, number> }}
 * `raw` is the label or the vector the severity came from (empty when assumed); `scores` holds the calculated score of every v3.x vector seen
 */
export function normalizeOsvSeverity(entries) {
  /** @type {Record<string, number>} */
  const scores = Object.create(null);
  /** @type {{ severity: Severity, raw: string, scale: "osv" | "cvss" }[]} */
  const resolved = [];
  for (const entry of (Array.isArray(entries) ? entries : []).slice(0, MAX_OSV_ENTRIES)) {
    const vectors = (Array.isArray(entry?.vectors) ? entry.vectors : []).filter(
      (v) => typeof v === "string",
    );
    let best = null;
    for (const vector of vectors.slice(0, 6)) {
      const score = cvss3BaseScore(vector);
      if (score === null) continue;
      scores[vector] = score;
      if (best === null || score > best.score) best = { score, vector };
    }
    const labelled = OSV.get(norm(entry?.label));
    if (labelled)
      resolved.push({
        severity: /** @type {Severity} */ (labelled),
        raw: norm(entry.label).slice(0, 60),
        scale: "osv",
      });
    else if (best !== null)
      resolved.push({
        severity: severityFromCvssScore(best.score).severity,
        raw: best.vector.slice(0, 60),
        scale: "cvss",
      });
  }
  const top = resolved.reduce(
    (acc, r) => (acc === null || SEVERITY_RANK[r.severity] > SEVERITY_RANK[acc.severity] ? r : acc),
    /** @type {(typeof resolved)[number] | null} */ (null),
  );
  return top
    ? {
        severity: top.severity,
        assumed: false,
        raw: top.raw,
        scale: top.scale,
        scores: { ...scores },
      }
    : { severity: "medium", assumed: true, raw: "", scale: "osv", scores: { ...scores } };
}

/** The platform severity of a secret type class (SPEC 5.7). NEVER critical in v1: critical would mean verified active. */
const SECRET_SEVERITY = Object.freeze({
  private_key: "high",
  aws_access_key: "high",
  gcp_service_account: "high",
  azure_storage_key: "high",
  github_token: "high",
  gitlab_token: "high",
  stripe_key: "high",
  slack_token: "medium",
  jwt: "medium",
  basic_auth_url: "medium",
  password_assignment: "medium",
});
/**
 * @param {string} typeClass one of SECRET_TYPE_CLASSES
 * @param {"low" | "medium" | "high"} [confidence] decides the generic classes: medium for high or medium confidence, else low
 * @returns {NormalizedSeverity}
 */
export function severityOfSecretType(typeClass, confidence = "medium") {
  const fixed = Object.hasOwn(SECRET_SEVERITY, typeClass)
    ? SECRET_SEVERITY[/** @type {keyof typeof SECRET_SEVERITY} */ (typeClass)]
    : undefined;
  if (fixed) return { severity: /** @type {Severity} */ (fixed), assumed: false };
  if (["generic_api_key", "high_entropy_string", "other"].includes(typeClass))
    return { severity: confidence === "low" ? "low" : "medium", assumed: false };
  return { ...UNMAPPED };
}

/** Maps a tool's HIGH / MEDIUM / LOW confidence (Bandit, gosec, Opengrep metadata). Unknown or missing is `medium`. */
export function normalizeConfidence(raw) {
  return /** @type {"low" | "medium" | "high"} */ (LEVEL3.get(norm(raw)) ?? "medium");
}

/** @param {Severity[]} list @returns {Severity} the highest (an empty list is `info`) */
export function highestSeverity(list) {
  let best = /** @type {Severity} */ ("info");
  for (const s of list) if (SEVERITY_RANK[s] > SEVERITY_RANK[best]) best = s;
  return best;
}

/** One step up, capped at high (two distinct tools agree, SE-13). */
export function raiseConfidence(confidence) {
  const next = Math.min(CONFIDENCE_RANK[confidence] + 1, CONFIDENCES.length - 1);
  return /** @type {"low" | "medium" | "high"} */ (CONFIDENCES[next]);
}
