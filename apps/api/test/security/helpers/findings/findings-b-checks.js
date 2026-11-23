/**
 * Findings checks of part B (lifecycle, review, approval, SOD, exceptions, comments) (ADR-008 area 19, docs/modules/findings/SPEC.md 14.1). Empty in the contract freeze (Part A0): the part
 * adds its checks HERE and changes only its own line of `expected.js`. Planned ids: FND-S02, FND-S07 to FND-S09, FND-S10 (rationales), FND-S11, FND-S15, FND-S16, FNDDB-05.
 *
 * A check is `{ id, name, run }`. `run(c)` receives the findings world (`findings-world.js`: the pipeline-db tenants A and B plus finding
 * factories) and returns the list of problems (empty means it passed). Every denial needs a control (the same write made legitimately
 * succeeds) so a check cannot pass vacuously.
 * @type {{ id: string, name: string, run: (c: any) => Promise<string[]> }[]}
 */
export const FINDINGS_B_CHECKS = [];
