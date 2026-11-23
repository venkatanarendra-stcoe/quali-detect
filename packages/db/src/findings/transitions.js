import {
  FINDING_REASON_CODES,
  FINDING_SEVERITY_RANK,
  FINDING_TRANSITIONS,
  FINDINGS_LIMITS,
  SLA_DEFAULT_HOURS,
  SLA_STOPPED_STATUSES,
  hasCredentialShape,
  isTransitionAllowed,
} from "@qmentisai/shared";
import { FindingConflictError, FindingNotFoundError } from "./errors.js";
import {
  FINDING_QUEUES,
  buildFindingMessage,
  enqueueFindingMessages,
  initiatorOf,
} from "./events.js";

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

/** The derived columns a caller may set together with a transition (Prisma field names). Everything else is refused. */
const SETTABLE_COLUMNS = Object.freeze([
  "claimedByUserId",
  "assigneeUserId",
  "assignedAt",
  "pendingReviewId",
  "pendingExceptionId",
  "activeExceptionId",
  "exceptionExpiresAt",
  "acceptedSeverity",
  "severityOverride",
  "absentCount",
  "fixClaimedAt",
  "verifiedAt",
  "reopenedAt",
  "reopenCount",
  "closedAt",
  "slaStartedAt",
  "slaDueAt",
  "slaDueSoonNotifiedAt",
  "slaBreachNotifiedAt",
]);

/** History reason code to the audit action it is recorded under (SPEC 11.4); `detected` is not audited per finding. */
export const AUDIT_ACTION_BY_REASON = Object.freeze({
  review_started: "finding.review_started",
  review_recorded: "finding.review_recorded",
  review_withdrawn: "finding.review_withdrawn",
  approved_tp: "finding.approval_decided",
  approved_fp: "finding.approval_decided",
  rejected: "finding.approval_decided",
  fp_reopened: "finding.review_started",
  assigned: "finding.assigned",
  reassigned: "finding.assigned",
  unassigned: "finding.unassigned",
  work_started: "finding.remediation_started",
  fix_submitted: "finding.fix_submitted",
  absent_in_complete_scan: "finding.auto_pending",
  verified: "finding.verified",
  recurred: "finding.reopened",
  rereview: "finding.review_started",
  risk_accepted: "finding.exception_decided",
  suppressed: "finding.exception_decided",
  risk_acceptance_expired: "finding.exception_expired",
  suppression_expired: "finding.exception_expired",
  revoked: "finding.exception_revoked",
  severity_increased: "finding.reopened",
});

const COMMIT = /^[0-9a-f]{7,64}$/;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

const addHours = (date, hours) => new Date(date.getTime() + hours * 3_600_000);

/**
 * THE central transition function (SPEC 6.2). It loads the row by tenant, workspace and id with FOR UPDATE, checks `expectedRev`,
 * checks `isTransitionAllowed`, sets `qm.finding_actor_type` for the transaction, updates the row (`rev + 1`), inserts the
 * `finding_status_history` row, the audit entry and the outbox row (`finding.status_changed`, a realtime hint), all in the caller's
 * transaction `tx`. No other code updates `findings.status`. The database triggers are the second lock.
 *
 * SLA bookkeeping (SL-2) is derived here so no caller forgets it: a stopped status (`SLA_STOPPED_STATUSES`) clears `sla_due_at`; a
 * reopen restarts the clock (`sla_started_at = now`, due = now + target of the effective severity, tenant rows over the defaults);
 * leaving a stopped status without a reopen keeps the clock off until a target is applied by an approval to an open status. A key in
 * `columns` always wins over the derived value.
 * @param {any} tx Prisma transaction client
 * @param {TransitionInput} input
 * @returns {Promise<{ findingId: string, from: string | null, to: string, rev: number, historyId: string }>}
 * @throws {FindingNotFoundError} the finding is not in this tenant and workspace
 * @throws {FindingConflictError} `stale_revision` or `transition_not_allowed`
 */
export async function transitionFinding(tx, input) {
  const {
    scope,
    findingId,
    expectedRev,
    to,
    actor,
    reasonCode,
    note,
    links = {},
    columns = {},
  } = input;
  if (
    !scope ||
    !UUID.test(scope.tenantId) ||
    !UUID.test(scope.workspaceId) ||
    !UUID.test(findingId)
  )
    throw new TypeError("transitionFinding needs a trusted scope and a finding id");
  if (actor?.type === "user" ? !UUID.test(actor.userId ?? "") : actor?.type !== "system")
    throw new TypeError("a user actor needs a user id");
  if (actor.type === "system" && !["ingestion", "sla", "expiry"].includes(actor.code))
    throw new TypeError("a system actor needs a code");
  if (!FINDING_REASON_CODES.includes(reasonCode)) throw new TypeError("unknown reason code");
  if (
    note !== undefined &&
    (note.length > FINDINGS_LIMITS.historyNoteMax || hasCredentialShape(note))
  )
    throw new TypeError("the note is too long or looks like a credential");
  for (const key of Object.keys(columns))
    if (!SETTABLE_COLUMNS.includes(key))
      throw new TypeError(`column "${key}" cannot be set by a transition`);

  // 1. the actor kind of THIS transaction (the database reads it; it fails closed to "user")
  await tx.$executeRaw`SELECT set_config('qm.finding_actor_type', ${actor.type}, true)`;

  // 2. the row, by tenant AND workspace AND id, locked
  const rows = await tx.$queryRaw`
    SELECT id, repository_id AS "repositoryId", pipeline_id AS "pipelineId", status::text AS status, rev, severity::text AS severity,
           tool_severity::text AS "toolSeverity", severity_override::text AS "severityOverride", sla_started_at AS "slaStartedAt", sla_due_at AS "slaDueAt"
    FROM findings
    WHERE tenant_id = ${scope.tenantId}::uuid AND workspace_id = ${scope.workspaceId}::uuid AND id = ${findingId}::uuid
    FOR UPDATE`;
  const row = rows[0];
  if (!row) throw new FindingNotFoundError();
  if (expectedRev !== undefined && expectedRev !== row.rev)
    throw new FindingConflictError("stale_revision");

  // 3. the transition itself: the shared table decides, and the reason must belong to it
  const target = to === null ? row.status : to;
  const allowed =
    to === null
      ? FINDING_TRANSITIONS.some((t) => t.to === null && t.from.includes(row.status)) &&
        actor.type === "user"
      : isTransitionAllowed(row.status, target, actor.type);
  const reasonOk = FINDING_TRANSITIONS.some(
    (t) =>
      t.reasons.includes(reasonCode) &&
      t.from.includes(row.status) &&
      (t.to === null ? to === null : t.to === target) &&
      t.actors.includes(actor.type),
  );
  if (!allowed || !reasonOk) throw new FindingConflictError("transition_not_allowed");

  // 4. derived columns
  const now = new Date();
  const data = { ...columns };
  if (data.severityOverride !== undefined) {
    const effective = data.severityOverride ?? row.toolSeverity;
    data.severity = effective;
    data.severityRank = FINDING_SEVERITY_RANK[effective];
  }
  const severity = data.severity ?? row.severity;
  if (!("slaDueAt" in columns) && !("slaStartedAt" in columns)) {
    if (SLA_STOPPED_STATUSES.includes(target)) data.slaDueAt = null;
    else if (target === "reopened" || (target === "approved" && row.slaDueAt === null)) {
      const targets = await slaOverrides(tx, scope.tenantId);
      const hours = Object.hasOwn(targets, severity)
        ? targets[severity]
        : SLA_DEFAULT_HOURS[severity];
      if (target === "reopened") {
        data.slaStartedAt = now;
        data.slaDueAt = typeof hours === "number" ? addHours(now, hours) : null;
      } else if (typeof hours === "number" && row.slaStartedAt) {
        // an approved true positive that had no clock (it passed through false_positive): it runs from first detection again
        data.slaDueAt = addHours(new Date(row.slaStartedAt), hours);
      }
    }
  }
  if (target === "reopened" && data.reopenedAt === undefined) data.reopenedAt = now;

  // 5. the update (the BEFORE UPDATE trigger checks the machine again, `rev + 1` and the identifying columns)
  const rev = row.rev + 1;
  await tx.finding.update({
    where: { tenantId_id: { tenantId: scope.tenantId, id: findingId } },
    data: { ...data, ...(to === null ? {} : { status: target }), rev },
  });

  // 6. history, audit and the hint, in the SAME transaction
  const commitSha = links.commitSha && COMMIT.test(links.commitSha) ? links.commitSha : null;
  const history = await tx.findingStatusHistory.create({
    data: {
      tenantId: scope.tenantId,
      workspaceId: scope.workspaceId,
      repositoryId: row.repositoryId,
      pipelineId: row.pipelineId,
      findingId,
      rev,
      fromStatus: row.status,
      toStatus: target,
      actorType: actor.type,
      actorUserId: actor.type === "user" ? actor.userId : null,
      actorCode: actor.type === "system" ? actor.code : null,
      reasonCode,
      note: note ?? null,
      executionId: links.executionId && UUID.test(links.executionId) ? links.executionId : null,
      commitSha,
    },
    select: { id: true },
  });
  const action = AUDIT_ACTION_BY_REASON[reasonCode];
  if (action)
    await tx.auditLog.create({
      data: {
        tenantId: scope.tenantId,
        actorType: actor.type,
        actorUserId: actor.type === "user" ? actor.userId : null,
        action,
        targetType: "finding",
        targetId: findingId,
        workspaceId: scope.workspaceId,
        metadata: {
          from: row.status,
          to: target,
          reason: reasonCode,
          rev,
          ...(actor.type === "system" ? { actor: actor.code } : {}),
        },
      },
    });
  await enqueueFindingMessages(tx, [
    {
      queue: FINDING_QUEUES.REALTIME,
      message: buildFindingMessage({
        kind: "event",
        type: "finding.status_changed",
        messageId: `finding-status-${findingId}-${rev}`,
        tenantId: scope.tenantId,
        workspaceId: scope.workspaceId,
        repositoryId: row.repositoryId,
        pipelineId: row.pipelineId,
        initiator: initiatorOf(actor),
        subject: { type: "finding", id: findingId },
        payload: {
          findingId,
          workspaceId: scope.workspaceId,
          fromStatus: row.status,
          toStatus: target,
          rev,
          actorType: actor.type,
        },
        now,
      }),
    },
  ]);
  return { findingId, from: row.status, to: target, rev, historyId: history.id };
}

/** The tenant's SLA rows by severity (hours). @param {any} tx @param {string} tenantId @returns {Promise<Record<string, number>>} */
async function slaOverrides(tx, tenantId) {
  const rows = await tx.findingSlaTarget.findMany({
    where: { tenantId },
    select: { severity: true, hours: true },
  });
  return Object.fromEntries(rows.map((r) => [r.severity, r.hours]));
}
