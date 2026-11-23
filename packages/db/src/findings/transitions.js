import { notImplemented } from "./not-implemented.js";

/**
 * @typedef {object} FindingScope the TRUSTED scope of every finding query: from the session or from the re-validated message, never from a body
 * @property {string} tenantId
 * @property {string} workspaceId
 *
 * @typedef {object} FindingActor
 * @property {"user" | "system"} type
 * @property {string} [userId] required for a user
 * @property {"ingestion" | "sla" | "expiry"} [code] required for a system actor
 *
 * @typedef {object} TransitionInput
 * @property {FindingScope} scope
 * @property {string} findingId
 * @property {number} [expectedRev] optimistic concurrency; a mismatch is `FINDING_STATE_CONFLICT` / `stale_revision`
 * @property {string | null} to target status (`null` only for the reassignment SM-10: the status stays)
 * @property {FindingActor} actor
 * @property {string} reasonCode one of FINDING_REASON_CODES
 * @property {string} [note] plain text, at most 2000 characters, credential shapes refused
 * @property {{ executionId?: string, commitSha?: string }} [links] soft references recorded in the history row
 * @property {Record<string, unknown>} [columns] the derived columns the transition sets with the status (claimed_by, assignee, pending ids, sla, counters...)
 */

/**
 * THE central transition function (SPEC 6.2). It loads the row by tenant, workspace and id with FOR UPDATE, checks `expectedRev`,
 * checks `isTransitionAllowed`, sets `qm.finding_actor_type` for the transaction, updates the row (`rev + 1`), inserts the
 * `finding_status_history` row, the audit entry and the outbox row, all in the caller's transaction `tx`. No other code updates
 * `findings.status`. The database triggers are the second lock. Part A1 implements it.
 * @param {any} tx Prisma transaction client
 * @param {TransitionInput} input
 * @returns {Promise<{ findingId: string, from: string | null, to: string, rev: number, historyId: string }>}
 */
export const transitionFinding = notImplemented("A1", "transitionFinding");
