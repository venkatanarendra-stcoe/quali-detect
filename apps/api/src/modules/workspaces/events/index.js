/** Domain events (declared; published once the transactional outbox exists). Audit logs record each change meanwhile. */
export const WORKSPACE_EVENT_TYPES = Object.freeze({
  CREATED: "organization.workspace.created",
  UPDATED: "organization.workspace.updated",
  ARCHIVED: "organization.workspace.archived",
  RESTORED: "organization.workspace.restored",
});
