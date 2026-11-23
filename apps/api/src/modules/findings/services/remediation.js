import { can } from "@qmentisai/shared";
import { AppError } from "../../../errors/app-error.js";
import { mayMoveAssigned } from "../policies/lifecycle.js";
import {
  forbidden,
  invalid,
  mapFindingError,
  refuseSecretText,
  runFindingWrite,
  stateConflict,
} from "./lifecycle-support.js";

/** The statuses a person may move with a remediation action (SM-12, SM-13). */
const START_FROM = Object.freeze(["assigned"]);
const SUBMIT_FROM = Object.freeze(["assigned", "in_remediation"]);

/** True when `text` holds no control character (the database CHECK of a PR link refuses them). @param {string} text */
const hasNoControlChars = (text) => {
  for (let i = 0; i < text.length; i += 1)
    if (text.charCodeAt(i) < 0x20 || text.charCodeAt(i) === 0x7f) return false;
  return true;
};

/**
 * The shape the database CHECK accepts for a pull request link: `https://host[/path]`, no whitespace or control character, no `@` or
 * `/` in the host part (so no userinfo). The shared Zod schema already refused credentials; this stops a value the CHECK would refuse
 * from turning into a 500.
 * @param {string} url
 */
export const isStorablePullRequestUrl = (url) =>
  hasNoControlChars(url) && /^https:\/\/[^\s@/]+(\/\S*)?$/.test(url);

/**
 * The assignment and remediation side of the findings write API (Part C, docs/modules/findings/SPEC.md 5.7 AS-1, AS-2, RM-1, RM-2, 8.2):
 * assign or reassign, unassign, start work, submit a fix, and the bulk assign. Every method runs the one write transaction of
 * `runFindingWrite` (workspace not archived, the finding locked by tenant, workspace and id, `expectedRev` checked, an overdue
 * acceptance expired first) and answers with the finding AS THE CALLER now sees it (the detail DTO with the per-caller
 * `lifecycle.allowedActions`). The route authorized the permission KEY in the finding's own workspace; the rules that need the data
 * (the status, who the assignee is, a deleted pipeline, the eligibility of the assignee) are checked here, inside the lock. Nothing here
 * can verify or reopen a finding: a submitted fix only moves it to `fixed_pending_verification`; a later eligible scan decides (RM-2).
 * @param {{
 *   repository: ReturnType<typeof import("../repositories/remediation.js").createFindingsRemediationRepository>,
 *   reads: ReturnType<typeof import("./read.js").createFindingsReadService>,
 *   resolvePermissions: (subject: any, workspaceId: string) => Promise<any>,
 *   clock?: () => Date,
 * }} deps `resolvePermissions` is the central authorization engine (`authz.service.resolveFor`)
 */
export function createFindingsRemediationService({
  repository,
  reads,
  resolvePermissions,
  clock = () => new Date(),
}) {
  const deps = { repository, clock };
  const detail = (actor, ref) => reads.get(actor, ref);

  /**
   * AS-1: the assignee is an active member of the tenant who holds `finding.remediate` in the finding's workspace (decided by the
   * central engine). One answer for "not a member", "a member of another tenant", "inactive" and "no permission".
   */
  async function requireEligibleAssignee(actor, workspaceId, assigneeUserId) {
    const subject = await repository.memberContext(actor.tenantId, assigneeUserId);
    if (!subject || subject.user.status !== "active")
      throw invalid("assignee_not_eligible", "assigneeUserId");
    const permissions = await resolvePermissions(subject, workspaceId);
    if (!can(permissions, "finding.remediate", { type: "workspace", workspaceId }))
      throw invalid("assignee_not_eligible", "assigneeUserId");
  }

  /** RM-1: the finding is in a status the action moves, then the caller is its assignee or also holds `finding.assign`. */
  const requireMover = (actor, workspaceId, finding, from) => {
    if (!from.includes(finding.status)) throw stateConflict("transition_not_allowed");
    const canAssign = can(actor.permissions, "finding.assign", { type: "workspace", workspaceId });
    if (
      !mayMoveAssigned({
        assigneeUserId: finding.assigneeUserId,
        callerUserId: actor.userId,
        canAssign,
      })
    )
      throw forbidden("not_assignee");
  };

  return Object.freeze({
    /**
     * `POST /findings/{id}/assignments` (SM-9, SM-10, SM-17). @param {any} actor @param {{ id: string, workspaceId: string }} ref
     * @param {{ assigneeUserId: string, note?: string, expectedRev: number }} body validated `assignBodySchema` output
     */
    async assign(actor, ref, body) {
      refuseSecretText({ note: body.note });
      await requireEligibleAssignee(actor, ref.workspaceId, body.assigneeUserId);
      await runFindingWrite(deps, actor, ref, {
        expectedRev: body.expectedRev,
        apply: (tx, finding, scope) =>
          repository.assignments.assign(tx, {
            scope,
            finding,
            assigneeUserId: body.assigneeUserId,
            assignedByUserId: actor.userId,
            note: body.note ?? null,
            expectedRev: finding.rev,
          }),
      });
      return detail(actor, ref);
    },

    /** `POST /findings/{id}/assignments/clear` (SM-11). @param {any} actor @param {{ id: string, workspaceId: string }} ref @param {{ note?: string, expectedRev: number }} body */
    async clear(actor, ref, body) {
      refuseSecretText({ note: body.note });
      await runFindingWrite(deps, actor, ref, {
        expectedRev: body.expectedRev,
        apply: (tx, finding, scope) =>
          repository.assignments.clear(tx, {
            scope,
            finding,
            userId: actor.userId,
            note: body.note ?? null,
            expectedRev: finding.rev,
          }),
      });
      return detail(actor, ref);
    },

    /** `POST /findings/{id}/remediation/start` (SM-12). @param {any} actor @param {{ id: string, workspaceId: string }} ref @param {{ expectedRev: number }} body */
    async start(actor, ref, body) {
      await runFindingWrite(deps, actor, ref, {
        expectedRev: body.expectedRev,
        before: (_tx, finding, scope) =>
          requireMover(actor, scope.workspaceId, finding, START_FROM),
        apply: (tx, finding, scope) =>
          repository.remediation.record(tx, {
            scope,
            finding,
            kind: "work_started",
            userId: actor.userId,
            expectedRev: finding.rev,
          }),
      });
      return detail(actor, ref);
    },

    /**
     * `POST /findings/{id}/remediation/submit` (SM-13, RM-1): a pull request link (https only), a ticket key and a note, all optional.
     * A deleted pipeline cannot verify a fix (5.13): `409 pipeline_deleted`. The finding then waits for a scan; it is never "fixed".
     * @param {any} actor @param {{ id: string, workspaceId: string }} ref
     * @param {{ pullRequestUrl?: string, ticketKey?: string, note?: string, expectedRev: number }} body validated `remediationSubmitBodySchema` output
     */
    async submit(actor, ref, body) {
      refuseSecretText({ note: body.note, pullRequestUrl: body.pullRequestUrl });
      if (body.pullRequestUrl !== undefined && !isStorablePullRequestUrl(body.pullRequestUrl))
        throw invalid("invalid_pull_request_url", "pullRequestUrl");
      await runFindingWrite(deps, actor, ref, {
        expectedRev: body.expectedRev,
        before: (_tx, finding, scope) =>
          requireMover(actor, scope.workspaceId, finding, SUBMIT_FROM),
        apply: async (tx, finding, scope) => {
          if (await repository.pipelineDeleted(tx, scope, finding.pipelineId))
            throw stateConflict("pipeline_deleted");
          return repository.remediation.record(tx, {
            scope,
            finding,
            kind: "fix_submitted",
            userId: actor.userId,
            pullRequestUrl: body.pullRequestUrl ?? null,
            ticketKey: body.ticketKey ?? null,
            note: body.note ?? null,
            expectedRev: finding.rev,
          });
        },
      });
      return detail(actor, ref);
    },

    /**
     * `POST /findings/bulk/assign` (D-29): at most 50 findings of ONE workspace, each locked, assigned and audited in its OWN
     * transaction; a finding the caller cannot see is reported as not found, never as forbidden. The assignee is checked once.
     * @param {any} actor @param {{ workspaceId: string, findingIds: string[], assigneeUserId: string, note?: string }} body
     */
    async bulkAssign(actor, body) {
      refuseSecretText({ note: body.note });
      await requireEligibleAssignee(actor, body.workspaceId, body.assigneeUserId);
      const results = [];
      for (const findingId of body.findingIds) {
        try {
          await runFindingWrite(
            deps,
            actor,
            { id: findingId, workspaceId: body.workspaceId },
            {
              apply: (tx, finding, scope) =>
                repository.assignments.assign(tx, {
                  scope,
                  finding,
                  assigneeUserId: body.assigneeUserId,
                  assignedByUserId: actor.userId,
                  note: body.note ?? null,
                  expectedRev: finding.rev,
                }),
            },
          );
          results.push({ findingId, ok: true });
        } catch (error) {
          const e = mapFindingError(error);
          if (!(e instanceof AppError)) throw e;
          results.push({
            findingId,
            ok: false,
            errorCode: e.code,
            ...(typeof e.details?.reason === "string" ? { reason: e.details.reason } : {}),
          });
        }
      }
      return { results };
    },
  });
}
