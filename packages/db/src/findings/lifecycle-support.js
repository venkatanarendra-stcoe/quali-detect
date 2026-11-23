import { SLA_DEFAULT_HOURS } from "@qmentisai/shared";
import {
  FINDING_QUEUES,
  buildFindingMessage,
  enqueueFindingMessages,
  initiatorOf,
} from "./events.js";

/**
 * Helpers shared by the Part B repositories (`reviews.js`, `exceptions.js`): the audit row of an action that is NOT a status change,
 * the domain event written to the outbox in the caller's transaction, and the SLA due date of a severity. Everything runs in the
 * caller's `tx`: a failure rolls the change, its history, its audit entry and its event back together (SPEC 8.2, FND-S14).
 */

const addHours = (date, hours) => new Date(date.getTime() + hours * 3_600_000);

/**
 * One audit entry for an action that does not change the status (the transition function audits the ones that do). `metadata`
 * holds ids and enums ONLY: never a rationale, a comment or a justification (SPEC 11.1 FS-5, FS-7).
 * @param {any} tx
 * @param {{ tenantId: string, workspaceId: string }} scope
 * @param {{ type: "user" | "system", userId?: string, code?: string }} actor
 * @param {string} action one of `FINDING_AUDIT_ACTIONS`
 * @param {string} findingId
 * @param {Record<string, string | number | boolean | null>} metadata
 */
export async function writeFindingAudit(tx, scope, actor, action, findingId, metadata) {
  await tx.auditLog.create({
    data: {
      tenantId: scope.tenantId,
      actorType: actor.type,
      actorUserId: actor.type === "user" ? actor.userId : null,
      action,
      targetType: "finding",
      targetId: findingId,
      workspaceId: scope.workspaceId,
      metadata: { ...metadata, ...(actor.type === "system" ? { actor: actor.code } : {}) },
    },
  });
}

/**
 * Writes one domain event to the `realtime` queue (the findings realtime room consumes it as a hint; the future notifications module
 * subscribes the same message). Payloads are ids, enums and the revision only.
 * @param {any} tx
 * @param {{ tenantId: string, workspaceId: string }} scope
 * @param {{ repositoryId: string, pipelineId: string, id: string }} finding
 * @param {{ type: "user" | "system", userId?: string, code?: string }} actor
 * @param {string} type message type of the contracts catalog
 * @param {string} messageId unique per change (`finding-<what>-<id>-<rev>`)
 * @param {Record<string, unknown>} payload validated by the catalog schema on the consumer side
 */
export async function emitFindingEvent(tx, scope, finding, actor, type, messageId, payload) {
  await enqueueFindingMessages(tx, [
    {
      queue: FINDING_QUEUES.REALTIME,
      message: buildFindingMessage({
        kind: "event",
        type,
        messageId,
        tenantId: scope.tenantId,
        workspaceId: scope.workspaceId,
        repositoryId: finding.repositoryId,
        pipelineId: finding.pipelineId,
        initiator: initiatorOf(actor),
        subject: { type: "finding", id: finding.id },
        payload,
      }),
    },
  ]);
}

/**
 * The SLA due date of `severity` for a clock that started at `startedAt` (tenant rows over the defaults), or null when the severity
 * has no target (SL-1, SL-2).
 * @param {any} tx
 * @param {string} tenantId
 * @param {string} severity
 * @param {Date} startedAt
 * @returns {Promise<Date | null>}
 */
export async function slaDueFor(tx, tenantId, severity, startedAt) {
  const own = await tx.findingSlaTarget.findFirst({
    where: { tenantId, severity },
    select: { hours: true },
  });
  const hours = own ? own.hours : SLA_DEFAULT_HOURS[severity];
  return typeof hours === "number" ? addHours(startedAt, hours) : null;
}
