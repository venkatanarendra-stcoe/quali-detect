/**
 * Top-risk formula (SPEC 6.6 B-4, O-3): risk points = 10 x critical + 5 x high + 2 x medium + 1 x low over OPEN findings, plus 3 x the
 * number of BREACHED critical or high findings. The number is called "risk points", not a probability. The weights live here and nowhere
 * else (they are an Open point of the SPEC and are printed in the UI tooltip and the PDF).
 */

/** Weight of one open finding per effective severity. `info` carries no weight. */
export const RISK_WEIGHTS = Object.freeze({ critical: 10, high: 5, medium: 2, low: 1, info: 0 });
/** Extra points per breached critical or high finding. */
export const RISK_BREACHED_CRITICAL_HIGH_BONUS = 3;

/** The formula as text for the tooltip, the `meta` of `GET /reporting/top-risk` and the PDF. */
export const RISK_FORMULA_TEXT =
  "risk points = 10 x critical + 5 x high + 2 x medium + 1 x low (open findings) + 3 x breached critical or high";

/**
 * @param {{ critical?: number, high?: number, medium?: number, low?: number, info?: number, breachedCriticalHigh?: number }} counts open counts per severity and the breached critical or high count
 * @returns {number} risk points (a non-negative integer)
 */
export function computeRiskScore(counts) {
  const n = (v) => (typeof v === "number" && Number.isFinite(v) && v > 0 ? Math.floor(v) : 0);
  return (
    n(counts.critical) * RISK_WEIGHTS.critical +
    n(counts.high) * RISK_WEIGHTS.high +
    n(counts.medium) * RISK_WEIGHTS.medium +
    n(counts.low) * RISK_WEIGHTS.low +
    n(counts.info) * RISK_WEIGHTS.info +
    n(counts.breachedCriticalHigh) * RISK_BREACHED_CRITICAL_HIGH_BONUS
  );
}

/**
 * Sort comparator of the top-risk list: higher score first; ties by the OLDER oldest-open-critical first (a repository with none sorts
 * after one that has), then by name (code unit order, so the order is stable everywhere).
 * @param {{ score: number, oldestOpenCriticalAt?: Date | string | null, name: string }} a
 * @param {{ score: number, oldestOpenCriticalAt?: Date | string | null, name: string }} b
 * @returns {number}
 */
export function compareTopRisk(a, b) {
  if (a.score !== b.score) return b.score - a.score;
  const ta = a.oldestOpenCriticalAt ? new Date(a.oldestOpenCriticalAt).getTime() : Infinity;
  const tb = b.oldestOpenCriticalAt ? new Date(b.oldestOpenCriticalAt).getTime() : Infinity;
  if (ta !== tb) return ta < tb ? -1 : 1;
  return a.name < b.name ? -1 : a.name > b.name ? 1 : 0;
}
