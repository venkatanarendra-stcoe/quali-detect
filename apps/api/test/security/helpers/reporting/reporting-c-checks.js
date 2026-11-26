/**
 * Reporting Part C (exports) checks: `RPT-S05` (redaction canary), `RPT-S06` (CSV and PDF safety), `RPT-S07` (export object scoping and
 * traversal), `RPT-S08` (limits, authenticated download, expiry), `RPT-S12`. Owned by Part C: add the checks here and set the `C` line of
 * `expected.js`. Part A0 only created the empty file so the aggregate imports.
 * @type {{ id: string, name: string, run: (c: any) => Promise<string[]> }[]}
 */
export const REPORTING_C_CHECKS = [];
