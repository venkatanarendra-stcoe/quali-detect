import { notImplemented } from "./not-implemented.js";

/**
 * Accept-risk and suppression exceptions (Part B).
 * @param {{ db: any }} deps
 */
export function createFindingExceptionsRepository({ db }) {
  void db;
  return Object.freeze({
    /** Inserts a `pending` exception and sets the finding's pending pointer (the status is unchanged). @type {(tx: any, input: object) => Promise<object>} */
    request: notImplemented("B", "exceptions.request"),
    /** Advances a pending exception to withdrawn, approved or rejected. @type {(tx: any, input: object) => Promise<object>} */
    decide: notImplemented("B", "exceptions.decide"),
    /** Ends an approved exception: expired, revoked or invalidated. @type {(tx: any, input: object) => Promise<object>} */
    end: notImplemented("B", "exceptions.end"),
    /** Approved exceptions whose `expires_at` has passed, in bounded batches (the expiry job). @type {(now: Date, limit: number) => Promise<Array<{ tenantId: string, workspaceId: string, findingId: string, exceptionId: string }>>} */
    dueForExpiry: notImplemented("B", "exceptions.dueForExpiry"),
  });
}
