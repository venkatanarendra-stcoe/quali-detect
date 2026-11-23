import { FINDINGS_C_ASSIGN_CHECKS } from "./findings-c-assign-checks.js";
import { FINDINGS_C_BOARD_CHECKS } from "./findings-c-board-checks.js";
import { FINDINGS_C_SLA_CHECKS } from "./findings-c-sla-checks.js";
import { FINDINGS_C_EVENTS_CHECKS } from "./findings-c-events-checks.js";

/**
 * Findings checks of part C (remediation, verification surface, SLA, board) (ADR-008 area 19, docs/modules/findings/SPEC.md 14.1): its
 * share of `FND-S08` (assignment and remediation transitions), `FND-S11` (idempotency and rate limits of its routes), `FND-S12` (the board
 * DTO and the advisory pending and stale state) and `FND-S14` (atomicity and the SLA events), split over the files of this part. The REAL
 * routes run behind the stub authentication chain of part B; every denial has a control (the same write made legitimately succeeds) so a
 * check cannot pass vacuously.
 *
 * A check is `{ id, name, run }`. `run(c)` receives the findings world (`findings-world.js`) and returns the list of problems (empty means
 * it passed).
 * @type {{ id: string, name: string, run: (c: any) => Promise<string[]> }[]}
 */
export const FINDINGS_C_CHECKS = [
  ...FINDINGS_C_ASSIGN_CHECKS,
  ...FINDINGS_C_EVENTS_CHECKS,
  ...FINDINGS_C_BOARD_CHECKS,
  ...FINDINGS_C_SLA_CHECKS,
];
