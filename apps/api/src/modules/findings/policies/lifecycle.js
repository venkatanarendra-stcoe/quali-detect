import { EXCEPTION_SOURCE_STATUSES, agentRunsOn } from "@qmentisai/shared";

/**
 * The per-CALLER lifecycle rules of the findings module (docs/modules/findings/SPEC.md 3.1, 5.6 to 5.8, 8.3), in pure functions so the
 * read side (the DTO's `lifecycle.allowedActions`, the Approvals queue's `canDecide`) and the write side (the services) use one
 * definition. The SERVER computes everything the UI shows as enabled, disabled or hidden; the UI never recomputes it. The rule of the
 * response, decided by the E mock: an action the caller can NEVER take (no permission, wrong status, not their finding) is OMITTED; an
 * action they may reasonably request but cannot take right now is listed with `allowed: false` and a `disabledReason` in plain words
 * (segregation of duties, a request already pending, "only the assignee").
 */

/** Words shown next to a disabled button (SPEC SOD-4, SCREENS). At most 200 characters (the DTO schema). */
export const DISABLED_REASONS = Object.freeze({
  separationOfDutiesReview:
    "You recorded a decision on this finding. Another lead must approve it.",
  separationOfDutiesException: "You requested this. Another lead must approve it.",
  requestPending: "A request is already pending for this finding.",
  reviewBlockedByRequest: "A request is pending for this finding. Decide it first.",
  assigneeOnly: "You can only move findings assigned to you.",
  pipelineDeleted: "The pipeline was deleted, so no scan can verify a fix.",
  advisoryPending: "Advice is already being prepared.",
});

/**
 * @typedef {object} LifecycleFacts what the computation needs about the finding and the caller (built by the mapper from the detail record)
 * @property {string} status the EFFECTIVE status (an expired acceptance reads as `reopened`)
 * @property {boolean} pipelineDeleted
 * @property {string} scanType
 * @property {string} severity
 * @property {string} callerUserId the authenticated user (never from a request body)
 * @property {string | null} claimedByUserId
 * @property {string | null} assigneeUserId
 * @property {{ reviewerUserId: string } | null} pendingReview the review awaiting approval
 * @property {{ requestedByUserId: string } | null} pendingException
 * @property {readonly string[]} sodUserIds every user who recorded a review or requested an exception on this finding (any round)
 * @property {string} [advisoryStatus] the advisory DTO status (`pending` disables a new request)
 */

/**
 * Whether `userId` may not approve or reject a decision on this finding (SPEC SOD-1, SOD-2): they recorded a review (any round) or
 * requested an exception on it. User ids only; roles, permissions and sessions play no part, and no role bypasses it.
 * @param {readonly string[]} sodUserIds @param {string} userId
 */
export const isSodBlocked = (sodUserIds, userId) => sodUserIds.includes(userId);

/**
 * RM-1: who may move a finding that is assigned (start work, submit a fix): its assignee, or a caller who also holds `finding.assign`
 * in the workspace. ONE definition for the per-caller `allowedActions` and for the remediation write service (Part C).
 * @param {{ assigneeUserId: string | null | undefined, callerUserId: string, canAssign: boolean }} input
 */
export const mayMoveAssigned = ({ assigneeUserId, callerUserId, canAssign }) =>
  (typeof assigneeUserId === "string" && assigneeUserId === callerUserId) || canAssign === true;

/**
 * `lifecycle.allowedActions` for ONE caller (SPEC 8.3).
 * @param {LifecycleFacts} f
 * @param {(key: string) => boolean} can permission check in the finding's workspace (the central engine)
 * @returns {Array<{ action: string, allowed: boolean, disabledReason?: string }>}
 */
export function computeAllowedActions(f, can) {
  /** @type {Array<{ action: string, allowed: boolean, disabledReason?: string }>} */
  const list = [];
  const add = (action, allowed = true, disabledReason = undefined) =>
    list.push({ action, allowed, ...(!allowed && disabledReason ? { disabledReason } : {}) });
  const s = f.status;
  const me = f.callerUserId;
  const reviewer = can("finding.review");
  const assigner = can("finding.assign");
  const remediator = can("finding.remediate");
  const pendingException = f.pendingException !== null;
  const blocked = isSodBlocked(f.sodUserIds, me);

  // ---- review (SM-2, SM-3, SM-4, SM-8, SM-18) ----
  if (reviewer && s === "new") add("claim");
  if (reviewer && s === "in_review" && f.claimedByUserId !== me) add("claim"); // a take-over (audited)
  if (reviewer && (s === "new" || s === "in_review"))
    add("record_review", !pendingException, DISABLED_REASONS.reviewBlockedByRequest);
  if (reviewer && s === "awaiting_approval" && f.pendingReview?.reviewerUserId === me)
    add("withdraw_review");
  if (s === "awaiting_approval" && f.pendingReview) {
    if (can("approval.approve"))
      add("approve_review", !blocked, DISABLED_REASONS.separationOfDutiesReview);
    if (can("approval.reject"))
      add("reject_review", !blocked, DISABLED_REASONS.separationOfDutiesReview);
  }
  if (reviewer && (s === "false_positive" || s === "reopened")) add("reopen_review");

  // ---- assignment and remediation (Part C enforces; the rules are computed here for one list) ----
  if (assigner && (s === "approved" || s === "reopened")) add("assign");
  if (assigner && (s === "assigned" || s === "in_remediation")) {
    add("reassign");
    add("unassign");
  }
  const mayMove = mayMoveAssigned({
    assigneeUserId: f.assigneeUserId,
    callerUserId: me,
    canAssign: assigner,
  });
  if (remediator && s === "assigned") add("start_work", mayMove, DISABLED_REASONS.assigneeOnly);
  if (remediator && (s === "assigned" || s === "in_remediation")) {
    if (f.pipelineDeleted) add("submit_fix", false, DISABLED_REASONS.pipelineDeleted);
    else add("submit_fix", mayMove, DISABLED_REASONS.assigneeOnly);
  }

  // ---- exceptions (SM-19, SM-20, SM-21) ----
  if (EXCEPTION_SOURCE_STATUSES.includes(s)) {
    if (can("finding.accept_risk"))
      add("request_accept_risk", !pendingException, DISABLED_REASONS.requestPending);
    if (can("finding.suppress"))
      add("request_suppression", !pendingException, DISABLED_REASONS.requestPending);
  }
  if (pendingException) {
    if (f.pendingException?.requestedByUserId === me) add("withdraw_exception");
    if (can("approval.approve"))
      add(
        "approve_exception",
        !blocked,
        f.pendingException?.requestedByUserId === me
          ? DISABLED_REASONS.separationOfDutiesException
          : DISABLED_REASONS.separationOfDutiesReview,
      );
    if (can("approval.reject"))
      add(
        "reject_exception",
        !blocked,
        f.pendingException?.requestedByUserId === me
          ? DISABLED_REASONS.separationOfDutiesException
          : DISABLED_REASONS.separationOfDutiesReview,
      );
  }
  if (s === "accepted_risk" && can("finding.accept_risk")) add("revoke_accept_risk");
  if (s === "suppressed" && can("finding.suppress")) add("revoke_suppression");

  // ---- comment and advice ----
  if (can("finding.comment")) add("comment");
  if (reviewer && agentRunsOn({ scanType: f.scanType, severity: f.severity }))
    add("request_advisory", f.advisoryStatus !== "pending", DISABLED_REASONS.advisoryPending);
  return list;
}

/**
 * `canDecide` and `cannotDecideReason` of one row of the Approvals queue for ONE caller (SPEC 8.1 `GET /approvals`): the caller needs
 * `approval.approve` or `approval.reject`, and must not be blocked by segregation of duties on that finding.
 * @param {{ canApprove: boolean, canReject: boolean, callerUserId: string, sodUserIds: readonly string[] }} input
 * @returns {{ canDecide: boolean, cannotDecideReason: "separation_of_duties" | "missing_permission" | null }}
 */
export function decideStateOf({ canApprove, canReject, callerUserId, sodUserIds }) {
  if (!canApprove && !canReject)
    return { canDecide: false, cannotDecideReason: "missing_permission" };
  if (isSodBlocked(sodUserIds, callerUserId))
    return { canDecide: false, cannotDecideReason: "separation_of_duties" };
  return { canDecide: true, cannotDecideReason: null };
}
