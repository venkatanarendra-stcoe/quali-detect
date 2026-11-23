import { ERROR_CODES } from "@qmentisai/contracts";
import { FindingConflictError, FindingNotFoundError } from "@qmentisai/db";
import { hasSecretShape } from "@qmentisai/shared";
import {
  AppError,
  ConflictError,
  ForbiddenError,
  NotFoundError,
} from "../../../errors/app-error.js";

/**
 * Shared machinery of the findings WRITE services (Part B): the error mapping of the repositories' domain errors to the API's codes,
 * the refusal of secret-shaped text, and the one write transaction every service goes through (workspace not archived, the finding
 * row locked by tenant, workspace and id, the lazy expiry of an overdue exception, the optimistic-concurrency check). Services never
 * build an HTTP response; they throw `AppError`s the central error handler renders.
 */

/** `FINDING_STATE_CONFLICT` (409) with the reason the UI maps to a message. @param {string} reason */
export const stateConflict = (reason) =>
  new AppError(
    ERROR_CODES.FINDING_STATE_CONFLICT,
    "The finding changed or the action is not allowed now.",
    {
      details: { reason },
    },
  );

/** `FORBIDDEN` (403) with a machine reason (`separation_of_duties`, `missing_permission`, `not_reviewer`, ...). @param {string} reason */
export const forbidden = (reason) =>
  new ForbiddenError("You do not have permission to do this.", { details: { reason } });

/** `VALIDATION_FAILED` (400) with `details.reason` and the offending field (the mock's shape). @param {string} reason @param {string} [field] @param {string} [message] */
export const invalid = (reason, field, message = "The request is invalid.") =>
  new AppError(ERROR_CODES.VALIDATION_FAILED, message, {
    details: { reason, ...(field ? { field } : {}) },
  });

/**
 * Refuses secret-shaped text (SPEC RV-1, FS-5): the shared schemas already refuse the shapes of the database CHECK; this is the WIDER
 * platform list of `@qmentisai/shared` (`hasSecretShape`: Stripe, Slack, JWT, quoted assignments, ...). A refused text is never stored,
 * never logged, never echoed.
 * @param {Record<string, string | null | undefined>} fields field name to text
 */
export function refuseSecretText(fields) {
  for (const [field, text] of Object.entries(fields))
    if (typeof text === "string" && hasSecretShape(text)) throw invalid("credential_shape", field);
}

/** Whether a database error is the SOD trigger of `finding_approvals` (the backstop of SPEC SOD-5). @param {any} error */
export const isSodTriggerError = (error) =>
  /separation_of_duties/.test(String(error?.message ?? "")) ||
  /separation_of_duties/.test(String(error?.meta?.message ?? ""));

/**
 * Maps a repository or database error to the API's error. Anything unknown is rethrown untouched (the central handler hides it).
 * @param {unknown} error
 */
export function mapFindingError(error) {
  if (error instanceof FindingNotFoundError) return new NotFoundError();
  if (error instanceof FindingConflictError) return stateConflict(error.reason);
  if (isSodTriggerError(error)) return forbidden("separation_of_duties");
  // the partial unique indexes (one pending review, one pending or approved exception per finding) lost a race
  if (/** @type {any} */ (error)?.code === "P2002") return stateConflict("already_decided");
  return error;
}

/**
 * The one write transaction. `check` and `apply` run INSIDE it with the finding locked and re-read, so two writers on a finding are
 * serialized by the row lock and the loser sees the winner's state:
 *  1. the workspace must not be archived (409 `CONFLICT`, `reason: workspace_archived`);
 *  2. the finding is locked by tenant, workspace and id (404 otherwise, identical for hidden, foreign and missing);
 *  3. `expectedRev` must equal the row's `rev` AS THE CLIENT SAW IT (`409 FINDING_STATE_CONFLICT / stale_revision`); an overdue
 *     acceptance is then expired lazily (EX-3: an expired acceptance is never treated as accepted) and the work continues on the
 *     refreshed row, so the client's first write after an expiry does not fail on the revision the expiry itself raised;
 *  4. `apply(tx, finding)` does the change (its repository calls pass `finding.rev` as the expected revision: the row is locked).
 * Errors of the domain are mapped to the API's.
 * @param {{ repository: ReturnType<typeof import("../repositories/lifecycle.js").createFindingsLifecycleRepository>, clock: () => Date }} deps
 * @param {{ tenantId: string }} actor
 * @param {{ id: string, workspaceId: string }} ref
 * @param {{ expectedRev?: number, apply: (tx: any, finding: any, scope: { tenantId: string, workspaceId: string }) => Promise<any>, before?: (tx: any, finding: any, scope: any) => Promise<void> }} work
 */
export async function runFindingWrite({ repository, clock }, actor, ref, work) {
  const scope = { tenantId: actor.tenantId, workspaceId: ref.workspaceId };
  try {
    return await repository.transaction(async (tx) => {
      if ((await repository.workspaceStatus(tx, scope)) === "archived")
        throw new ConflictError("The workspace is archived.", {
          details: { reason: "workspace_archived" },
        });
      let finding = await repository.lockFinding(tx, scope, ref.id);
      // checks that decide BEFORE the revision (the segregation-of-duties refusal is a 403 whatever the revision)
      await work.before?.(tx, finding, scope);
      if (work.expectedRev !== undefined && finding.rev !== work.expectedRev)
        throw stateConflict("stale_revision");
      const expired = await repository.exceptions.expireIfDue(tx, scope, finding, clock());
      if (expired.expired) finding = await repository.lockFinding(tx, scope, ref.id);
      return await work.apply(tx, finding, scope);
    });
  } catch (error) {
    throw mapFindingError(error);
  }
}

/**
 * Audits a refused decision (`finding.approval_denied`, SPEC SOD-4, 11.4) OUTSIDE the failed transaction, so the row survives the
 * rollback: a segregation-of-duties refusal (`FORBIDDEN / separation_of_duties`), or a lost race or stale revision
 * (`FINDING_STATE_CONFLICT`). Both user ids and the decision id, ids and enums only. A failure of the audit write never hides the
 * refusal itself.
 * @param {ReturnType<typeof import("../repositories/lifecycle.js").createFindingsLifecycleRepository>} repository
 * @param {{ tenantId: string, userId: string, requestId?: string, ip?: string }} actor
 * @param {{ id: string, workspaceId: string }} ref
 * @param {any} error the thrown (already mapped) error
 * @param {{ kind: "review" | "exception", decisionId: string | null, counterpartUserId?: string | null }} entry
 */
export async function auditApprovalRefusal(repository, actor, ref, error, entry) {
  const reason =
    error?.code === ERROR_CODES.FORBIDDEN || error?.code === ERROR_CODES.FINDING_STATE_CONFLICT
      ? error.details?.reason
      : null;
  if (typeof reason !== "string") return;
  await repository
    .recordApprovalDenied(
      { tenantId: actor.tenantId, workspaceId: ref.workspaceId },
      {
        approverUserId: actor.userId,
        findingId: ref.id,
        reason,
        requestId: actor.requestId,
        ip: actor.ip,
        ...entry,
      },
    )
    .catch(() => {});
}
