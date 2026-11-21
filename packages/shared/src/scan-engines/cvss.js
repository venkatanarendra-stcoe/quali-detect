/**
 * CVSS v3.0 and v3.1 base-score calculator (docs/modules/scan-engines/SPEC.md 5.7 "OSV record", owner decision D-5, OQ-4): the public
 * FIRST formula, pure, no network, no dependency. A tool that reports only a vector (OSV) is scored here so its severity can be
 * normalized like every other tool's.
 *
 * Strict: a vector must start with `CVSS:3.0/` or `CVSS:3.1/` and carry each of the eight base metrics exactly once with a legal
 * value; the optional temporal and environmental metrics (`E`, `RL`, `RC`, `CR`, `IR`, `AR`, `MAV` ...) are accepted once each with a
 * one-letter value and IGNORED (real GHSA data carries `/E:H`; the BASE score is what is computed); anything else (a repeated or
 * unknown metric, a missing base metric, a version 2 or 4 vector, extra text) is NOT scored (`null`), so a hostile vector can neither
 * crash the mapper nor choose a severity. CVSS v4.0 has no calculator in v1 (SPEC 5.7: its
 * lookup tables are not approved): {@link parseCvssVersion} names the version so the caller can mark the severity as assumed.
 */

const WEIGHTS = Object.freeze({
  AV: Object.freeze({ N: 0.85, A: 0.62, L: 0.55, P: 0.2 }),
  AC: Object.freeze({ L: 0.77, H: 0.44 }),
  UI: Object.freeze({ N: 0.85, R: 0.62 }),
  CIA: Object.freeze({ H: 0.56, L: 0.22, N: 0 }),
  PR_UNCHANGED: Object.freeze({ N: 0.85, L: 0.62, H: 0.27 }),
  PR_CHANGED: Object.freeze({ N: 0.85, L: 0.68, H: 0.5 }),
});
const METRICS = Object.freeze(["AV", "AC", "PR", "UI", "S", "C", "I", "A"]);
const LEGAL = Object.freeze({
  AV: "NALP",
  AC: "LH",
  PR: "NLH",
  UI: "NR",
  S: "UC",
  C: "HLN",
  I: "HLN",
  A: "HLN",
});
/** Optional metrics that do not change the base score (CVSS v3.1 sections 2 and 4). */
const IGNORED = Object.freeze(
  new Set(["E", "RL", "RC", "CR", "IR", "AR", "MAV", "MAC", "MPR", "MUI", "MS", "MC", "MI", "MA"]),
);
const MAX_VECTOR_LENGTH = 200;

/**
 * The CVSS version a vector claims, or null (used to tell a v4 vector, which is not scored, from garbage).
 * @param {unknown} vector @returns {"2.0" | "3.0" | "3.1" | "4.0" | null}
 */
export function parseCvssVersion(vector) {
  if (typeof vector !== "string" || vector.length > MAX_VECTOR_LENGTH) return null;
  const m = /^CVSS:(3\.0|3\.1|4\.0)\//.exec(vector);
  if (m) return /** @type {"3.0" | "3.1" | "4.0"} */ (m[1]);
  return /^AV:[NAL]\/AC:[HML]\/Au:[MSN]\//.test(vector) ? "2.0" : null;
}

/**
 * Round-up: the smallest number with one decimal not below `x`, computed on integers to avoid float noise (FIRST v3.1 specification, appendix
 * A). Used for v3.0 as well: over all 2592 base vectors the v3.0 ceiling rule and this rule give identical scores (checked exhaustively on
 * 2026-11-21), so one rule serves both versions.
 */
function roundUp31(x) {
  const i = Math.round(x * 100000);
  return i % 10000 === 0 ? i / 100000 : (Math.floor(i / 10000) + 1) / 10;
}
/**
 * @param {unknown} vector
 * @returns {Map<string, string> | null} the eight base metrics, or null when the vector is not a strict v3.x base vector
 */
function parseV3(vector) {
  if (typeof vector !== "string" || vector.length > MAX_VECTOR_LENGTH) return null;
  const parts = vector.split("/");
  if (parts.length < 9 || parts.length > 23) return null;
  if (parts[0] !== "CVSS:3.0" && parts[0] !== "CVSS:3.1") return null;
  /** @type {Map<string, string>} */
  const found = new Map();
  for (const part of parts.slice(1)) {
    const [key, value, ...rest] = part.split(":");
    if (rest.length > 0 || found.has(key) || typeof value !== "string" || value.length !== 1)
      return null;
    if (IGNORED.has(key)) {
      if (!/^[A-Z]$/.test(value)) return null;
    } else if (!METRICS.includes(key) || !LEGAL[key].includes(value)) return null;
    found.set(key, value);
  }
  return METRICS.every((k) => found.has(k)) ? found : null;
}

/**
 * The CVSS v3.x base score of a vector.
 * @param {unknown} vector `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`
 * @returns {number | null} 0.0 to 10.0 with one decimal, or null when the vector is not a strict v3.0 or v3.1 base vector
 */
export function cvss3BaseScore(vector) {
  const m = parseV3(vector);
  if (m === null) return null;
  const changed = m.get("S") === "C";
  const iss =
    1 -
    (1 - WEIGHTS.CIA[/** @type {"H"} */ (m.get("C"))]) *
      (1 - WEIGHTS.CIA[/** @type {"H"} */ (m.get("I"))]) *
      (1 - WEIGHTS.CIA[/** @type {"H"} */ (m.get("A"))]);
  const impact = changed ? 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15 : 6.42 * iss;
  const pr = (changed ? WEIGHTS.PR_CHANGED : WEIGHTS.PR_UNCHANGED)[
    /** @type {"N"} */ (m.get("PR"))
  ];
  const exploitability =
    8.22 *
    WEIGHTS.AV[/** @type {"N"} */ (m.get("AV"))] *
    WEIGHTS.AC[/** @type {"L"} */ (m.get("AC"))] *
    pr *
    WEIGHTS.UI[/** @type {"N"} */ (m.get("UI"))];
  if (impact <= 0) return 0;
  return changed
    ? roundUp31(Math.min(1.08 * (impact + exploitability), 10))
    : roundUp31(Math.min(impact + exploitability, 10));
}
