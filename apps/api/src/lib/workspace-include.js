/**
 * Relations loaded with every workspace so the list and detail views can show the member count and the owner's name
 * without extra requests. The member count covers active roster entries only; the owner is always an active member.
 */
export const WORKSPACE_INCLUDE = Object.freeze({
  _count: { select: { members: { where: { status: "active" } } } },
  owner: { include: { user: { select: { name: true } } } },
});
