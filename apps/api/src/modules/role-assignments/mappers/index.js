/**
 * @param {"user" | "group"} kind
 * @param {any} row assignment with `role` and `membership.user` (user) or `group` (group) loaded
 */
export const toAssignmentDto = (kind, row) => ({
  id: row.id,
  subjectType: kind,
  subject:
    kind === "user"
      ? { id: row.userId, name: row.membership.user.name, email: row.membership.user.email }
      : { id: row.groupId, name: row.group.name, email: null },
  role: { id: row.role.id, key: row.role.key, name: row.role.name, kind: row.role.kind },
  scopeType: row.scopeType,
  workspaceId: row.workspaceId,
  status: row.status,
  expiresAt: row.expiresAt,
  createdByUserId: row.createdByUserId,
  createdAt: row.createdAt,
});
