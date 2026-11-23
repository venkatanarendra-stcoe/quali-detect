/**
 * Findings checks of part F (cross-cutting sweep, documentation) (ADR-008 area 19, docs/modules/findings/SPEC.md 14.1). Empty in the contract freeze (Part A0): the part
 * adds its checks HERE and changes only its own line of `expected.js`. Planned ids: the cross-cutting checks no part owns (FND-S01 write routes sweep, FND-S14, FND-S16 if B is late).
 *
 * A check is `{ id, name, run }`. `run(c)` receives the findings world (`findings-world.js`: the pipeline-db tenants A and B plus finding
 * factories) and returns the list of problems (empty means it passed). Every denial needs a control (the same write made legitimately
 * succeeds) so a check cannot pass vacuously.
 * @type {{ id: string, name: string, run: (c: any) => Promise<string[]> }[]}
 */
export const FINDINGS_F_CHECKS = [];
