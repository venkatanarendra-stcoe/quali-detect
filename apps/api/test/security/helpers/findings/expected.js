/**
 * The Findings checks of the security suite (ADR-008 area 19, docs/modules/findings/SPEC.md 14.1, 16.1), split by building part so the parts
 * register their checks in their OWN files and never edit each other's. Part A0 pre-assigns every range here; a part changes only its own
 * line when it adds checks (separate lines merge cleanly). `security.test.js` expects `909 + sum` checks and the registration block fails
 * with the name of the part whose count differs, so a missing or forgotten check is found at once.
 *
 * Ids (the owner of each prefix registers it, spec 14.1):
 *  - A0: `FNDA0-NN` (contract freeze: migration shape, immutability, state machine in the database, SOD trigger, the restricted agent role,
 *    shared-package properties, the frozen surface);
 *  - A (A1): `FND-S01` (read part), `FND-S03`..`FND-S06`, `FND-S12` (reads), `FND-S13`, `FND-S17`, `FNDDB-01`..`FNDDB-03`;
 *  - B: `FND-S02`, `FND-S07`..`FND-S09`, `FND-S10` (rationales), `FND-S11`, `FND-S15`, `FND-S16`, `FNDDB-05`;
 *  - C: its share of `FND-S08` and `FND-S14` (assignment and SLA events);
 *  - D: `FPA-S01`..`FPA-S07`, `FND-S10` (agent parts);
 *  - F: `FND-S01` (write routes sweep), `FND-S14`, `FND-S16` when B is late, and anything cross-cutting.
 * A letter suffix splits a spec id into checks (`FND-S04a`); a check id is unique across the whole suite.
 * @type {Readonly<{ A0: number, A: number, B: number, C: number, D: number, F: number }>}
 */
export const EXPECTED_FINDINGS_CHECKS = Object.freeze({ A0: 15, A: 0, B: 0, C: 0, D: 12, F: 0 });

/** The part names in registration order. */
export const FINDINGS_PARTS = Object.freeze(["A0", "A", "B", "C", "D", "F"]);

/** Sum of the expected counts, added to the base count of the suite (909 before the Findings module). */
export const FINDINGS_CHECKS_TOTAL = Object.values(EXPECTED_FINDINGS_CHECKS).reduce(
  (a, b) => a + b,
  0,
);
