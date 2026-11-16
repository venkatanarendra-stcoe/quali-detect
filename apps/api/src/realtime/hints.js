import { buildExecutionRoom, buildTenantRoom } from "@qmentisai/shared";
import { SERVER_EVENTS } from "./constants.js";
import { HINT_SCHEMAS } from "./schemas.js";

/**
 * Message types that produce a hint. `pipeline.execution.started|completed|cancel_requested` also reach the queue; they are
 * acknowledged without a hint, because the matching `status_changed` hint (which carries the revision) always accompanies them.
 */
export const HINT_MESSAGE_TYPES = Object.freeze([
  "pipeline.execution.status_changed",
  "scan.task.status_changed",
  "pipeline.execution.log_appended",
]);

/**
 * Builds the hint of a verified message. The ROOMS come from `target` (the row loaded from the database for the message's
 * tenant), never from the message; the payload is rebuilt field by field and then parsed by the strict allowlist, so nothing
 * but the documented hint fields can leave the server (no log text, SHA, ref, finding or user data).
 * @param {{ type: string, occurredAt: string, payload: any }} message validated envelope
 * @param {{ tenantId: string, workspaceId: string, executionId: string, pipelineId: string }} target from the database
 * @returns {{ event: string, rooms: string[], payload: object } | null} null when the type produces no hint
 */
export function buildHint(message, target) {
  const { payload } = message;
  const workspaceRoom = buildTenantRoom({
    tenantId: target.tenantId,
    workspaceId: target.workspaceId,
  });
  const executionRoom = buildExecutionRoom({
    tenantId: target.tenantId,
    workspaceId: target.workspaceId,
    executionId: target.executionId,
  });
  switch (message.type) {
    case "pipeline.execution.status_changed":
      return {
        event: SERVER_EVENTS.EXECUTION_CHANGED,
        rooms: [workspaceRoom, executionRoom],
        payload: HINT_SCHEMAS[SERVER_EVENTS.EXECUTION_CHANGED].parse({
          executionId: target.executionId,
          workspaceId: target.workspaceId,
          pipelineId: target.pipelineId,
          status: payload.status,
          rev: payload.rev,
          at: message.occurredAt,
        }),
      };
    case "scan.task.status_changed":
      return {
        event: SERVER_EVENTS.TASK_CHANGED,
        rooms: [executionRoom],
        payload: HINT_SCHEMAS[SERVER_EVENTS.TASK_CHANGED].parse({
          executionId: target.executionId,
          taskId: payload.taskId,
          scanType: payload.scanType,
          status: payload.status,
          rev: payload.rev,
        }),
      };
    case "pipeline.execution.log_appended":
      return {
        event: SERVER_EVENTS.LOG_APPENDED,
        rooms: [executionRoom],
        payload: HINT_SCHEMAS[SERVER_EVENTS.LOG_APPENDED].parse({
          executionId: target.executionId,
          lastSeq: payload.lastSeq,
        }),
      };
    default:
      return null;
  }
}
