/**
 * Vulnerability DB mirror vocabulary and the staleness policy (docs/modules/scan-engines/SPEC.md 5.12, SE-33, SE-35, SE-37, SE-38 as
 * rewritten 2026-11-19, D-22). Pure: no I/O, no clock of its own (the caller passes `now`).
 */

/** Tools that have a mirrored database in v1 (D-21: Grype is deferred and has NO mirror; the refresh job refuses it). */
export const DB_TOOL_IDS = Object.freeze(["trivy", "osv-scanner"]);

/** Lifecycle of a snapshot row (SE-33). Transitions are one-way: candidate to active or rejected, active to retired. */
export const DB_SNAPSHOT_STATUSES = Object.freeze(["candidate", "active", "retired", "rejected"]);

/**
 * The platform audit action of the quarantine alert (SPEC scan-engines 5.12, SE-39, owner decision D-24 (f)): a vulnerability DB
 * refresh was blocked because the upstream snapshot declares or contains quarantined (non-commercial or unstated-licence) data. It
 * ends in `_denied`, so the Root Console audit log derives the result `failure` for it and its `result` filter finds it.
 */
export const DB_ALERT_ACTIONS = Object.freeze({ QUARANTINE_DENIED: "scan_db.quarantine_denied" });

/** Where the quarantine was found: in the sources the upstream DECLARES (nothing downloaded) or in the inspected snapshot. */
export const DB_ALERT_STAGES = Object.freeze(["declared", "inspected"]);

/** Fixed reason words of a rejected candidate (never free text, never upstream text). */
export const DB_REJECT_REASONS = Object.freeze([
  "integrity_mismatch",
  "integrity_unverified",
  "too_large",
  "empty",
  "too_small",
  "too_old",
  "future_built",
  "archive_hostile",
  "record_invalid",
  "quarantined_source",
  "source_not_allowed",
  "canary_failed",
  "abandoned",
]);

/** The staleness tiers of the active snapshot, by the age of its UPSTREAM build time (SE-38). */
export const DB_STALENESS_TIERS = Object.freeze(["fresh", "aging", "stale", "expired"]);

/**
 * Thresholds in days (Recommended, OQ-6): `aging` > 3 and `stale` > 14 are the numbers of SE-38; `expired` > 30 is a third number added
 * by Part F because four tiers were asked for and the SPEC names two (decision for the owner, SPEC 17.p).
 */
export const DEFAULT_DB_STALENESS_DAYS = Object.freeze({ aging: 3, stale: 14, expired: 30 });

const DAY_MS = 86_400_000;

/** @param {unknown} value a Date, an ISO string or epoch milliseconds @returns {number} NaN when unreadable */
function toEpochMs(value) {
  if (value instanceof Date) return value.getTime();
  if (typeof value === "string") return Date.parse(value);
  return typeof value === "number" ? value : Number.NaN;
}

/** @param {Date | string} value @returns {string} */
const isoOf = (value) => (value instanceof Date ? value.toISOString() : String(value));

/**
 * @param {Partial<{ aging: number, stale: number, expired: number }>} [days]
 * @returns {{ aging: number, stale: number, expired: number }}
 * @throws {RangeError} when the thresholds are not positive and strictly increasing
 */
export function resolveDbStalenessDays(days = {}) {
  const t = { ...DEFAULT_DB_STALENESS_DAYS, ...days };
  const ok =
    Number.isFinite(t.aging) &&
    Number.isFinite(t.stale) &&
    Number.isFinite(t.expired) &&
    t.aging > 0 &&
    t.aging < t.stale &&
    t.stale < t.expired;
  if (!ok) throw new RangeError("Staleness thresholds must be positive and strictly increasing.");
  return t;
}

/**
 * The tier of a snapshot. An unreadable or missing build time is `expired` (fail-safe: the result is partial, never complete), a
 * build time in the future counts as age 0.
 * @param {{ builtAt: Date | string | number | null | undefined, now: Date | number }} input
 * @param {Partial<{ aging: number, stale: number, expired: number }>} [days]
 * @returns {{ tier: "fresh" | "aging" | "stale" | "expired", ageSeconds: number | null }}
 */
export function classifyDbStaleness({ builtAt, now }, days) {
  const t = resolveDbStalenessDays(days);
  const built = toEpochMs(builtAt);
  const at = toEpochMs(now);
  if (!Number.isFinite(built) || !Number.isFinite(at)) return { tier: "expired", ageSeconds: null };
  const ageMs = Math.max(0, at - built);
  const tier =
    ageMs > t.expired * DAY_MS
      ? "expired"
      : ageMs > t.stale * DAY_MS
        ? "stale"
        : ageMs > t.aging * DAY_MS
          ? "aging"
          : "fresh";
  return { tier, ageSeconds: Math.floor(ageMs / 1000) };
}

/**
 * What a tier does to a tool run (SE-38 rewritten, D-22): NOTHING EVER FAILS. Every tier but `fresh` is `partial` with reason
 * `db_stale`, the result is `incomplete` and therefore not resolution eligible (ER-24); the tool still runs. `notice` is a fixed key
 * the UI maps to text ("DB older than N days" for aging, "vulnerability data is out of date" for stale and expired).
 * An unknown tier is treated as `expired`.
 * @param {string} tier
 * @returns {{ tier: string, toolStatus: "succeeded" | "partial", reason: "db_stale" | null, resultIncomplete: boolean, resolutionEligible: boolean, failsScan: false, notice: "db_aging" | "db_out_of_date" | null }}
 */
export function dbStalenessEffect(tier) {
  const known = DB_STALENESS_TIERS.includes(tier) ? tier : "expired";
  if (known === "fresh")
    return {
      tier: known,
      toolStatus: "succeeded",
      reason: null,
      resultIncomplete: false,
      resolutionEligible: true,
      failsScan: false,
      notice: null,
    };
  return {
    tier: known,
    toolStatus: "partial",
    reason: "db_stale",
    resultIncomplete: true,
    resolutionEligible: false,
    failsScan: false,
    notice: known === "aging" ? "db_aging" : "db_out_of_date",
  };
}

/**
 * The provenance a result may carry for a snapshot (SE-37): the digest and the dates only. No store path, no source URL, no reject
 * reason, no internal id.
 * @param {{ toolId: string, sha256: string, upstreamBuiltAt: Date, fetchedAt: Date, sources?: any[] }} snapshot
 * @param {{ now: Date | number, days?: Partial<{ aging: number, stale: number, expired: number }> }} options
 */
export function dbProvenance(snapshot, { now, days }) {
  const { tier } = classifyDbStaleness({ builtAt: snapshot.upstreamBuiltAt, now }, days);
  return {
    toolId: snapshot.toolId,
    dbSnapshotSha256: snapshot.sha256,
    dbBuiltAt: isoOf(snapshot.upstreamBuiltAt),
    dbFetchedAt: isoOf(snapshot.fetchedAt),
    stalenessTier: tier,
    attributionRequired: Array.isArray(snapshot.sources)
      ? snapshot.sources.some((s) => s?.attributionRequired === true)
      : false,
  };
}
