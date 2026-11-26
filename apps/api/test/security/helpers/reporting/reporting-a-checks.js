/**
 * Reporting Part A (rollup core) checks: `RPT-S09` (rollup idempotency and tenant isolation) and `RPT-S10` (equivalence with live, backfill
 * equals incremental, DST day boundaries, rebuild after a time-zone change). Owned by Part A: add the checks here and set the `A` line of
 * `expected.js`. Part A0 only created the empty file so the aggregate imports.
 * @type {{ id: string, name: string, run: (c: any) => Promise<string[]> }[]}
 */
export const REPORTING_A_CHECKS = [];
