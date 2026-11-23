/**
 * Findings checks of part A1 (core: identity, ingestion, reads, seed) (ADR-008 area 19, docs/modules/findings/SPEC.md 14.1). Empty in the contract freeze (Part A0): the part
 * adds its checks HERE and changes only its own line of `expected.js`. Planned ids: FND-S01 (read part), FND-S03 to FND-S06, FND-S12 (reads), FND-S13, FND-S17, FNDDB-01 to FNDDB-03.
 *
 * A check is `{ id, name, run }`. `run(c)` receives the findings world (`findings-world.js`: the pipeline-db tenants A and B plus finding
 * factories) and returns the list of problems (empty means it passed). Every denial needs a control (the same write made legitimately
 * succeeds) so a check cannot pass vacuously.
 * @type {{ id: string, name: string, run: (c: any) => Promise<string[]> }[]}
 */
export const FINDINGS_A_CHECKS = [];
