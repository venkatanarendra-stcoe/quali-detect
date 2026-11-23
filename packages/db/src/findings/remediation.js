import { notImplemented } from "./not-implemented.js";

/**
 * Remediation and verification rows (Part C; verification rows are WRITTEN by the ingestion path of A1).
 * @param {{ db: any }} deps
 */
export function createFindingRemediationRepository({ db }) {
  void db;
  return Object.freeze({
    /** Inserts a `work_started` or `fix_submitted` record. @type {(tx: any, input: object) => Promise<object>} */
    record: notImplemented("C", "remediation.record"),
    /** Verification records of one finding, newest first. @type {(scope: import("./transitions.js").FindingScope, findingId: string) => Promise<object[]>} */
    verifications: notImplemented("C", "remediation.verifications"),
  });
}
