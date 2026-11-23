import { EXPECTED_FINDINGS_CHECKS, FINDINGS_PARTS } from "./expected.js";
import { FINDINGS_A0_CHECKS } from "./findings-a0-checks.js";
import { FINDINGS_A_CHECKS } from "./findings-a-checks.js";
import { FINDINGS_B_CHECKS } from "./findings-b-checks.js";
import { FINDINGS_C_CHECKS } from "./findings-c-checks.js";
import { FINDINGS_D_CHECKS } from "./findings-d-checks.js";
import { FINDINGS_AMEND_CHECKS } from "./findings-amend-checks.js";
import { FINDINGS_F_CHECKS } from "./findings-f-checks.js";

export { buildFindingsWorld } from "./findings-world.js";
export { EXPECTED_FINDINGS_CHECKS, FINDINGS_CHECKS_TOTAL } from "./expected.js";

/** The checks of each part (docs/modules/findings/SPEC.md 16.1): every part registers in its own file. */
const BY_PART = Object.freeze({
  A0: FINDINGS_A0_CHECKS,
  A: FINDINGS_A_CHECKS,
  B: FINDINGS_B_CHECKS,
  C: FINDINGS_C_CHECKS,
  D: FINDINGS_D_CHECKS,
  F: FINDINGS_F_CHECKS,
  AM: FINDINGS_AMEND_CHECKS,
});

/**
 * Every Findings check in registration order. Throws, naming the part, when a part's file holds a different number of checks than its
 * line of `expected.js` says (a forgotten or an unexpected check).
 * @type {{ id: string, name: string, run: (c: any) => Promise<string[]> }[]}
 */
export const FINDINGS_CHECKS = FINDINGS_PARTS.flatMap((part) => {
  const checks = BY_PART[part];
  if (checks.length !== EXPECTED_FINDINGS_CHECKS[part])
    throw new Error(
      `Findings suite part ${part} registers ${checks.length} checks but expected.js says ${EXPECTED_FINDINGS_CHECKS[part]}`,
    );
  return checks;
});
