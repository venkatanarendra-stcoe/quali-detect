import { SERVER_EVENTS } from "./constants.js";
import { HINT_SCHEMAS } from "./schemas.js";

/**
 * The findings room and its hints (docs/modules/findings/SPEC.md 9.5, FS-8, FND-S15). A room is named `findings:workspace:<tenantId>:
 * <workspaceId>`; the NAME IS BUILT HERE from ids that were validated (the principal's tenant, a workspace id from the subscribe payload
 * or from the database row of a verified message), never from a client string. A socket joins it only after `finding.view` is checked
 * in that workspace by the central engine, and the check is repeated at every re-validation pass (a revoked permission leaves the room).
 * A hint carries ids, the status word, the revision and a TYPE only: no title, rationale, comment, snippet or user data can be emitted
 * (the strict `finding.changed` schema refuses any other key).
 */

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

/**
 * @param {{ tenantId: string, workspaceId: string }} input
 * @returns {string}
 */
export function buildFindingsRoom({ tenantId, workspaceId }) {
  if (!UUID.test(String(tenantId)) || !UUID.test(String(workspaceId)))
    throw new TypeError("A findings room needs a tenant id and a workspace id.");
  return `findings:workspace:${tenantId}:${workspaceId}`;
}

/** The finding events that produce a hint (the `realtime` queue carries them; every other type is acknowledged without one). */
export const FINDING_HINT_MESSAGE_TYPES = Object.freeze([
  "finding.created",
  "finding.status_changed",
  "finding.review_recorded",
  "finding.approval_decided",
  "finding.assigned",
  "finding.fix_submitted",
  "finding.verified",
  "finding.reopened",
  "finding.exception_requested",
  "finding.exception_decided",
  "finding.exception_expired",
  "finding.comment_added",
  "finding.advisory.completed",
]);

/** Whether a message type belongs to the findings hints. @param {string} type */
export const isFindingHintType = (type) => FINDING_HINT_MESSAGE_TYPES.includes(type);

/**
 * The hint of a verified finding message. The ROOM comes from `target` (the finding row loaded from the database for the message's
 * tenant), never from the message; the payload is rebuilt field by field and parsed by the strict allowlist.
 * @param {{ type: string, payload: any }} message validated envelope
 * @param {{ tenantId: string, workspaceId: string, findingId: string }} target from the database
 * @returns {{ event: string, rooms: string[], payload: object }}
 */
export function buildFindingHint(message, target) {
  const { payload } = message;
  return {
    event: SERVER_EVENTS.FINDING_CHANGED,
    rooms: [buildFindingsRoom(target)],
    payload: HINT_SCHEMAS[SERVER_EVENTS.FINDING_CHANGED].parse({
      type: message.type,
      findingId: target.findingId,
      workspaceId: target.workspaceId,
      ...(message.type === "finding.status_changed" ? { status: payload.toStatus } : {}),
      ...(Number.isInteger(payload.rev) ? { rev: payload.rev } : {}),
    }),
  };
}
