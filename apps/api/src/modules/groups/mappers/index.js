/** @param {any} group group with `_count.members` */
export const toGroupDto = (group) => ({
  id: group.id,
  name: group.name,
  description: group.description,
  memberCount: group._count?.members ?? 0,
  createdAt: group.createdAt,
  updatedAt: group.updatedAt,
});

/** @param {any} member group member with `membership.user` */
export const toGroupMemberDto = (member) => ({
  userId: member.userId,
  email: member.membership.user.email,
  name: member.membership.user.name,
  addedAt: member.createdAt,
});
