import { notImplemented } from "./not-implemented.js";

/**
 * Review, approval and comment rows (Part B). Every write method runs inside the caller's transaction and uses `transitionFinding`
 * for the status.
 * @param {{ db: any }} deps
 */
export function createFindingReviewsRepository({ db }) {
  void db;
  return Object.freeze({
    /** Inserts a review (`pending`) and sets the finding's pending pointer. @type {(tx: any, input: object) => Promise<object>} */
    record: notImplemented("B", "reviews.record"),
    /** Marks the pending review `withdrawn`. @type {(tx: any, input: object) => Promise<object>} */
    withdraw: notImplemented("B", "reviews.withdraw"),
    /** Inserts the approval row (the SOD trigger may refuse) and advances the review state. @type {(tx: any, input: object) => Promise<object>} */
    decide: notImplemented("B", "reviews.decide"),
    /** Distinct users who recorded a review on the finding (any round), for the SOD service check. @type {(scope: import("./transitions.js").FindingScope, findingId: string, tx?: any) => Promise<string[]>} */
    reviewerIds: notImplemented("B", "reviews.reviewerIds"),
    /** `GET /approvals`. @type {(scope: import("./transitions.js").FindingScope, query: object) => Promise<{ items: object[], totalItems?: number, nextCursor?: string | null }>} */
    pendingApprovals: notImplemented("B", "reviews.pendingApprovals"),
    /** Inserts a comment. @type {(tx: any, input: object) => Promise<object>} */
    addComment: notImplemented("B", "reviews.addComment"),
  });
}
