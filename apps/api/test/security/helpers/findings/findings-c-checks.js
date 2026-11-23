/**
 * Findings checks of part C (remediation, SLA, board) (ADR-008 area 19, docs/modules/findings/SPEC.md 14.1). Empty in the contract freeze (Part A0): the part
 * adds its checks HERE and changes only its own line of `expected.js`. Planned ids: its share of FND-S08 and FND-S14.
 *
 * A check is `{ id, name, run }`. `run(c)` receives the findings world (`findings-world.js`: the pipeline-db tenants A and B plus finding
 * factories) and returns the list of problems (empty means it passed). Every denial needs a control (the same write made legitimately
 * succeeds) so a check cannot pass vacuously.
 * @type {{ id: string, name: string, run: (c: any) => Promise<string[]> }[]}
 */
export const FINDINGS_C_CHECKS = [];
