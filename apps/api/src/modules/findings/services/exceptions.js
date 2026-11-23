import { FINDINGS_LIMITS, can } from "@qmentisai/shared";
import { NotFoundError } from "../../../errors/app-error.js";
import { isSodBlocked } from "../policies/lifecycle.js";
import {
  auditApprovalRefusal,
  forbidden,
  invalid,
  refuseSecretText,
  runFindingWrite,
  stateConflict,
} from "./lifecycle-support.js";

const DAY_MS = 86_400_000;
/** The permission that requests, and revokes, an exception of each kind (SPEC 3.1, 8.2). */
const KEY_BY_KIND = Object.freeze({
  accept_risk: "finding.accept_risk",
  suppress: "finding.suppress",
});

/**
 * Accept-risk and suppression exceptions (Part B, docs/modules/findings/SPEC.md 5.8, EX-1 to EX-6, 8.2): request, withdraw, approve,
 * reject, revoke. A pending request does NOT change the finding's status; only an approval does (SM-19, SM-20), through the central
 * transition function with the user as the actor. The expiry (EX-3) is done by `exceptions.expireIfDue` (the job, and lazily by the
 * write transaction of every other write), never by this service. Segregation of duties (SOD-1) covers exceptions too: the approver is
 * not the requester and not any reviewer of the finding.
 * @param {{
 *   repository: ReturnType<typeof import("../repositories/lifecycle.js").createFindingsLifecycleRepository>,
 *   reads: ReturnType<typeof import("./read.js").createFindingsReadService>,
 *   resolvePermissions: (subject: any, workspaceId: string) => Promise<any>,
 *   clock?: () => Date,
 * }} deps `resolvePermissions` is the central authorization engine (`authz.service.resolveFor`)
 */
export function createFindingsExceptionsService({
  repository,
  reads,
  resolvePermissions,
  clock = () => new Date(),
}) {
  const deps = { repository, clock };

  /** The caller must hold the key of the exception's KIND in the finding's workspace (the route checked the body's kind for a request). */
  const requireKindKey = (actor, workspaceId, kind) => {
    if (!can(actor.permissions, KEY_BY_KIND[kind], { type: "workspace", workspaceId }))
      throw forbidden("missing_permission");
  };

  /** EX-1: the expiry window. `accept_risk` needs one (at most 180 days); `suppress` may have one (at most 365). */
  function checkExpiry(kind, expiresAt, now) {
    const max =
      (kind === "accept_risk"
        ? FINDINGS_LIMITS.acceptRiskMaxDays
        : FINDINGS_LIMITS.suppressMaxDays) * DAY_MS;
    if (expiresAt === undefined) {
      if (kind === "accept_risk") throw invalid("expiry_out_of_range", "expiresAt");
      return null;
    }
    const t = Date.parse(expiresAt);
    if (!Number.isFinite(t) || t <= now.getTime() || t > now.getTime() + max)
      throw invalid("expiry_out_of_range", "expiresAt");
    return new Date(t);
  }

  /** The approver hint (EX-1): an active member of the tenant who holds `approval.approve` in the workspace and is not the requester. */
  async function checkApproverHint(actor, workspaceId, approverUserId) {
    if (approverUserId === actor.userId)
      throw invalid("approver_not_eligible", "requestedApproverUserId");
    const subject = await repository.memberContext(actor.tenantId, approverUserId);
    if (!subject || subject.user.status !== "active")
      throw invalid("approver_not_eligible", "requestedApproverUserId");
    const permissions = await resolvePermissions(subject, workspaceId);
    if (!can(permissions, "approval.approve", { type: "workspace", workspaceId }))
      throw invalid("approver_not_eligible", "requestedApproverUserId");
  }

  /** @param {any} actor @param {{ id: string, workspaceId: string }} ref @param {string} exceptionId @param {any} body @param {"approve" | "reject"} decision */
  async function decide(actor, ref, exceptionId, body, decision) {
    refuseSecretText({ comment: body.comment });
    let exception = null;
    try {
      await runFindingWrite(deps, actor, ref, {
        expectedRev: body.expectedRev,
        before: async (tx, finding, scope) => {
          exception = await repository.findException(tx, scope, finding.id, exceptionId);
          if (!exception) throw new NotFoundError();
          const blocked = await repository.reviews.sodBlockedIds(scope, finding.id, tx);
          if (isSodBlocked(blocked, actor.userId)) throw forbidden("separation_of_duties");
        },
        apply: (tx, finding, scope) => {
          const e = /** @type {any} */ (exception);
          if (e.state !== "pending" || finding.pendingExceptionId !== exceptionId)
            throw stateConflict("already_decided");
          // a request whose expiry has already passed can only be rejected: approving it would accept a risk that is already over
          if (decision === "approve" && e.expiresAt && e.expiresAt.getTime() <= clock().getTime())
            throw stateConflict("transition_not_allowed");
          return repository.exceptions.decide(tx, {
            scope,
            finding,
            exception: e,
            approverUserId: actor.userId,
            decision,
            comment: body.comment,
            expectedRev: finding.rev,
          });
        },
      });
    } catch (error) {
      await auditApprovalRefusal(repository, actor, ref, error, {
        kind: "exception",
        decisionId: exceptionId,
        counterpartUserId: /** @type {any} */ (exception)?.requestedByUserId ?? null,
      });
      throw error;
    }
    return reads.get(actor, ref);
  }

  return Object.freeze({
    /**
     * `POST /findings/{id}/exceptions`: a pending request (the status is unchanged). `finding.accept_risk` for `kind: accept_risk`,
     * `finding.suppress` for `suppress`.
     * @param {any} actor @param {{ id: string, workspaceId: string }} ref @param {any} body validated `createExceptionBodySchema` output
     */
    async request(actor, ref, body) {
      requireKindKey(actor, ref.workspaceId, body.kind);
      refuseSecretText({
        justification: body.justification,
        compensatingControls: body.compensatingControls,
      });
      const now = clock();
      const expiresAt = checkExpiry(body.kind, body.expiresAt, now);
      if (body.requestedApproverUserId)
        await checkApproverHint(actor, ref.workspaceId, body.requestedApproverUserId);
      await runFindingWrite(deps, actor, ref, {
        expectedRev: body.expectedRev,
        apply: (tx, finding, scope) =>
          repository.exceptions.request(tx, {
            scope,
            finding,
            kind: body.kind,
            requestedByUserId: actor.userId,
            justification: body.justification,
            compensatingControls: body.compensatingControls ?? null,
            expiresAt,
            requestedApproverUserId: body.requestedApproverUserId ?? null,
            now,
          }),
      });
      return reads.get(actor, ref);
    },

    /** `POST /findings/{id}/exceptions/{exceptionId}/withdraw`: only the requester, only while pending. */
    async withdraw(actor, ref, exceptionId) {
      await runFindingWrite(deps, actor, ref, {
        before: async (tx, finding, scope) => {
          const exception = await repository.findException(tx, scope, finding.id, exceptionId);
          if (!exception) throw new NotFoundError();
          if (exception.requestedByUserId !== actor.userId) throw forbidden("not_requester");
        },
        apply: async (tx, finding, scope) => {
          const exception = await repository.findException(tx, scope, finding.id, exceptionId);
          if (
            !exception ||
            exception.state !== "pending" ||
            finding.pendingExceptionId !== exceptionId
          )
            throw stateConflict("already_decided");
          return repository.exceptions.withdraw(tx, {
            scope,
            finding,
            exception,
            userId: actor.userId,
          });
        },
      });
      return reads.get(actor, ref);
    },

    /** `POST /findings/{id}/exceptions/{exceptionId}/approve` (SM-19, SM-20, SOD-1). */
    approve: (actor, ref, exceptionId, body) => decide(actor, ref, exceptionId, body, "approve"),
    /** `POST /findings/{id}/exceptions/{exceptionId}/reject` (a comment is required by the schema; SOD-1). */
    reject: (actor, ref, exceptionId, body) => decide(actor, ref, exceptionId, body, "reject"),

    /**
     * `POST /findings/{id}/exceptions/{exceptionId}/revoke` (EX-4, SM-21): the key of the exception's KIND, a reason, and the exception
     * must still be the active one.
     * @param {any} actor @param {{ id: string, workspaceId: string }} ref @param {string} exceptionId @param {{ reason: string, expectedRev: number }} body
     */
    async revoke(actor, ref, exceptionId, body) {
      refuseSecretText({ reason: body.reason });
      await runFindingWrite(deps, actor, ref, {
        expectedRev: body.expectedRev,
        before: async (tx, finding, scope) => {
          const exception = await repository.findException(tx, scope, finding.id, exceptionId);
          if (!exception) throw new NotFoundError();
          requireKindKey(actor, ref.workspaceId, exception.kind);
        },
        apply: async (tx, finding, scope) => {
          const exception = await repository.findException(tx, scope, finding.id, exceptionId);
          if (
            !exception ||
            exception.state !== "approved" ||
            finding.activeExceptionId !== exceptionId ||
            !["accepted_risk", "suppressed"].includes(finding.status)
          )
            throw stateConflict("transition_not_allowed");
          return repository.exceptions.revoke(tx, {
            scope,
            finding,
            exception,
            userId: actor.userId,
            reason: body.reason,
            expectedRev: finding.rev,
          });
        },
      });
      return reads.get(actor, ref);
    },
  });
}
