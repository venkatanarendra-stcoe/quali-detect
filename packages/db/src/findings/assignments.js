import { notImplemented } from "./not-implemented.js";

/**
 * Assignment rows, the board and the SLA settings (Part C).
 * @param {{ db: any }} deps
 */
export function createFindingAssignmentsRepository({ db }) {
  void db;
  return Object.freeze({
    /** Ends the open assignment (if any), inserts a new one and sets the finding's assignee. @type {(tx: any, input: object) => Promise<object>} */
    assign: notImplemented("C", "assignments.assign"),
    /** Ends the open assignment. @type {(tx: any, input: object) => Promise<object>} */
    clear: notImplemented("C", "assignments.clear"),
    /** `GET /remediation/board` and one column page. @type {(scope: import("./transitions.js").FindingScope, query: object) => Promise<object>} */
    board: notImplemented("C", "assignments.board"),
    /** The tenant's SLA targets with defaults. @type {(scope: { tenantId: string }) => Promise<Array<{ severity: string, hours: number | null, isDefault: boolean }>>} */
    readSlaTargets: notImplemented("C", "assignments.readSlaTargets"),
    /** Replaces the tenant's SLA targets (audited by the caller). @type {(tx: any, scope: { tenantId: string }, targets: Array<{ severity: string, hours: number }>, userId: string) => Promise<void>} */
    writeSlaTargets: notImplemented("C", "assignments.writeSlaTargets"),
    /** Open findings due soon or breached that were not notified yet, bounded (the SLA sweep). @type {(now: Date, limit: number) => Promise<object[]>} */
    dueForSweep: notImplemented("C", "assignments.dueForSweep"),
  });
}
