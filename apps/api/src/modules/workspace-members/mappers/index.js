/** @param {any} member workspace member with `membership.user` loaded */
export const toWorkspaceMemberDto = (member) => ({
  userId: member.userId,
  email: member.membership.user.email,
  name: member.membership.user.name,
  status: member.status,
  addedAt: member.createdAt,
});
