/**
 * Reporting Part B (read API) checks: `RPT-S01` (isolation, identical 404), `RPT-S02` (permission matrix 403), `RPT-S03` (no-leak DTO),
 * `RPT-S04` (role grants in use), `RPT-S11` (cache scoping and invalidation). Owned by Part B: add the checks here and set the `B` line of
 * `expected.js`. Part A0 only created the empty file so the aggregate imports.
 * @type {{ id: string, name: string, run: (c: any) => Promise<string[]> }[]}
 */
export const REPORTING_B_CHECKS = [];
