/**
 * Tenant view of a user = their membership. Users are global, so a tenant never sees or edits global profile data of a
 * person who has not accepted (the name stays hidden while the membership is only `invited`).
 * @param {any} membership tenant membership with `user` loaded
 */
export const toUserDto = (membership) => ({
  userId: membership.userId,
  email: membership.user.email,
  name: membership.status === "invited" ? null : membership.user.name,
  status: membership.status,
  joinedAt: membership.joinedAt,
  invitedAt: membership.createdAt,
  lastLoginAt: membership.status === "active" ? membership.user.lastLoginAt : null,
});
