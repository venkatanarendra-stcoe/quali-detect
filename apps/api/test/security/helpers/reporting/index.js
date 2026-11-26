import { buildFindingsWorld } from "../findings/findings-world.js";
import { EXPECTED_REPORTING_CHECKS, REPORTING_PARTS } from "./expected.js";
import { REPORTING_A0_CHECKS } from "./reporting-a0-checks.js";
import { REPORTING_A_CHECKS } from "./reporting-a-checks.js";
import { REPORTING_AM_CHECKS } from "./reporting-am-checks.js";
import { REPORTING_B_CHECKS } from "./reporting-b-checks.js";
import { REPORTING_C_CHECKS } from "./reporting-c-checks.js";
import { REPORTING_E_CHECKS } from "./reporting-e-checks.js";

export { EXPECTED_REPORTING_CHECKS, REPORTING_CHECKS_TOTAL } from "./expected.js";

/**
 * The world of the Reporting checks: the tenants A and B of the pipelines database world plus the finding factories of the Findings world
 * (the reporting tables hang off the same tenants, pipelines and findings). A part that needs more builds on it in its own file.
 * @param {any} db the suite's Prisma client
 */
export const buildReportingWorld = (db) => buildFindingsWorld(db);

/** The checks of each part (docs/modules/reporting-dashboards/SPEC.md 16.2): every part registers in its own file. */
const BY_PART = Object.freeze({
  A0: REPORTING_A0_CHECKS,
  A: REPORTING_A_CHECKS,
  B: REPORTING_B_CHECKS,
  AM: REPORTING_AM_CHECKS,
  C: REPORTING_C_CHECKS,
  E: REPORTING_E_CHECKS,
});

/**
 * Every Reporting check in registration order. Throws, naming the part, when a part's file holds a different number of checks than its
 * line of `expected.js` says (a forgotten or an unexpected check).
 * @type {{ id: string, name: string, run: (c: any) => Promise<string[]> }[]}
 */
export const REPORTING_CHECKS = REPORTING_PARTS.flatMap((part) => {
  const checks = BY_PART[part];
  if (checks.length !== EXPECTED_REPORTING_CHECKS[part])
    throw new Error(
      `Reporting suite part ${part} registers ${checks.length} checks but expected.js says ${EXPECTED_REPORTING_CHECKS[part]}`,
    );
  return checks;
});
