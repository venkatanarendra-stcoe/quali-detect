/**
 * Domain events. `CREATED` is published through the transactional outbox (committed with the workspace, delivered by the
 * relay to the notification worker); the others are declared and follow the same path when a consumer needs them.
 * Payload schemas live in the message catalog (@qmentisai/contracts).
 */
export const WORKSPACE_EVENT_TYPES = Object.freeze({
  CREATED: "organization.workspace.created",
  UPDATED: "organization.workspace.updated",
  ARCHIVED: "organization.workspace.archived",
  RESTORED: "organization.workspace.restored",
});
