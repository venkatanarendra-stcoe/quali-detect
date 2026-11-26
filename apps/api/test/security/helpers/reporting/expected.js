/**
 * The Reporting checks of the security suite (ADR-008 area 20, docs/modules/reporting-dashboards/SPEC.md 16.2), split by building part so the
 * parts register their checks in their OWN files and never edit each other's, the manner of `helpers/findings/expected.js`. `security.test.js`
 * expects `909 + findings + sum` checks and the registration block fails with the NAME OF THE PART whose count differs, so a missing or
 * forgotten check is found at once.
 *
 * `EXPECTED_REPORTING_CHECKS` is what is BUILT today: a part that is not built yet is 0 and its file exports an empty array (the aggregate
 * counts only registered parts and the suite stays green). A part sets ITS OWN LINE when it adds checks (separate lines merge cleanly).
 * `PLANNED_REPORTING_CHECKS` is the pre-assignment of the SPEC (16.2): which ids belong to which part, so the parts do not collide; it is
 * documentation and is compared with nothing.
 *
 * Ids (the owner of each prefix registers it):
 *  - A0: `RPTA0-NN` (contract freeze: migration shape, composite keys, CHECKs, the redaction-safe views, the two roles and their grants, the
 *    provisioning script, shared-package properties (periods and DST, `csvSafeCell`, lifecycle groups, risk formula, schemas, metrics,
 *    templates), message schemas, the frozen surface and the flags);
 *  - A (rollup core): `RPT-S09` (rollup idempotency and tenant isolation), `RPT-S10` (equivalence with live, backfill equals incremental, DST
 *    day boundaries, rebuild after a time-zone change);
 *  - B (read API): `RPT-S01` (isolation, identical 404), `RPT-S02` (permission matrix 403), `RPT-S03` (no-leak DTO), `RPT-S04` (role grants in
 *    use: the read pool cannot write or read evidence), `RPT-S11` (cache scoping and invalidation);
 *  - AM (amendment of A0/A/B, SPEC 17.5): `RPTAM-NN` (the three added views, their grants and tenant scoping, GitHub connection counts, forward-only state series, amended DTOs);
 *  - C (exports): `RPT-S05` (redaction canary in rollup rows, DTOs, CSV and PDF), `RPT-S06` (CSV and PDF safety), `RPT-S07` (export object
 *    scoping and traversal), `RPT-S08` (limits, authenticated download, expiry), `RPT-S12`;
 *  - D (UI): none, UI tests are outside the suite;
 *  - E (cross-cutting): `RPT-S13`, `RPT-S14` and the sweeps.
 * A letter suffix splits a spec id into checks (`RPT-S05a`); a check id is unique across the whole suite.
 * @type {Readonly<{ A0: number, A: number, B: number, AM: number, C: number, E: number }>}
 */
export const EXPECTED_REPORTING_CHECKS = Object.freeze({
  A0: 16,
  A: 9,
  B: 11,
  AM: 7,
  C: 16,
  E: 12,
});

/** What SPEC 16.2 pre-assigns to each part (documentation; not asserted). */
export const PLANNED_REPORTING_CHECKS = Object.freeze({
  A: Object.freeze(["RPT-S09", "RPT-S10"]),
  B: Object.freeze(["RPT-S01", "RPT-S02", "RPT-S03", "RPT-S04", "RPT-S11"]),
  C: Object.freeze(["RPT-S05", "RPT-S06", "RPT-S07", "RPT-S08", "RPT-S12"]),
  D: Object.freeze([]),
  E: Object.freeze(["RPT-S13", "RPT-S14"]),
});

/** The part names in registration order. */
export const REPORTING_PARTS = Object.freeze(["A0", "A", "B", "AM", "C", "E"]);

/** Sum of the expected counts, added to the base count of the suite (909 before Findings plus the Findings total). */
export const REPORTING_CHECKS_TOTAL = Object.values(EXPECTED_REPORTING_CHECKS).reduce(
  (a, b) => a + b,
  0,
);
