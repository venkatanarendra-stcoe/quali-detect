import { toPrismaPaging } from "../../../lib/query.js";

const GROUP_SORT = {
  name: (d) => ({ name: d }),
  createdAt: (d) => ({ createdAt: d }),
  memberCount: (d) => ({ members: { _count: d } }),
};
const MEMBER_SORT = {
  name: (d) => ({ membership: { user: { name: d } } }),
  email: (d) => ({ membership: { user: { email: d } } }),
  createdAt: (d) => ({ createdAt: d }),
};
const withCount = { _count: { select: { members: true } } };
const memberInclude = {
  membership: { include: { user: { select: { id: true, email: true, name: true } } } },
};

/** Data access for groups; every query carries the tenantId. @param {{ db: any }} deps */
export function createGroupRepository({ db }) {
  return Object.freeze({
    async list({ tenantId, q, sort, page, pageSize }) {
      const where = { tenantId, ...(q ? { name: { contains: q, mode: "insensitive" } } : {}) };
      const [items, totalItems] = await Promise.all([
        db.group.findMany({
          where,
          include: withCount,
          orderBy: sort.map(({ field, direction }) => GROUP_SORT[field](direction)),
          ...toPrismaPaging({ page, pageSize }),
        }),
        db.group.count({ where }),
      ]);
      return { items, totalItems };
    },
    findById: ({ tenantId, id }, client = db) =>
      client.group.findFirst({ where: { tenantId, id }, include: withCount }),
    create: ({ tenantId, data }, client = db) =>
      client.group.create({ data: { ...data, tenantId }, include: withCount }),
    async update({ tenantId, id, data }, client = db) {
      const result = await client.group.updateMany({ where: { tenantId, id }, data });
      return result.count === 0
        ? null
        : client.group.findFirst({ where: { tenantId, id }, include: withCount });
    },
    /** Deletes the group; its members and role assignments cascade. @returns {Promise<number>} */
    async delete({ tenantId, id }, client = db) {
      return (await client.group.deleteMany({ where: { tenantId, id } })).count;
    },
    async listMembers({ tenantId, groupId, q, sort, page, pageSize }) {
      const where = {
        tenantId,
        groupId,
        ...(q
          ? {
              membership: {
                user: {
                  OR: [
                    { name: { contains: q, mode: "insensitive" } },
                    { email: { contains: q, mode: "insensitive" } },
                  ],
                },
              },
            }
          : {}),
      };
      const [items, totalItems] = await Promise.all([
        db.groupMember.findMany({
          where,
          include: memberInclude,
          orderBy: sort.map(({ field, direction }) => MEMBER_SORT[field](direction)),
          ...toPrismaPaging({ page, pageSize }),
        }),
        db.groupMember.count({ where }),
      ]);
      return { items, totalItems };
    },
    findActiveMembership: ({ tenantId, userId }, client = db) =>
      client.tenantMembership.findFirst({
        where: { tenantId, userId, status: "active" },
        select: { id: true },
      }),
    /** Active, unexpired role assignments of the group (what a new member would inherit). */
    async listLiveAssignments({ tenantId, groupId, now }, client = db) {
      const rows = await client.groupRoleAssignment.findMany({
        where: {
          tenantId,
          groupId,
          status: "active",
          OR: [{ expiresAt: null }, { expiresAt: { gt: now } }],
        },
        include: { role: { select: { permissions: { select: { permissionKey: true } } } } },
      });
      return rows.map((a) => ({
        scopeType: a.scopeType,
        workspaceId: a.workspaceId,
        permissionKeys: a.role.permissions.map((p) => p.permissionKey),
      }));
    },
    upsertMember: ({ tenantId, groupId, userId, addedByUserId }, client = db) =>
      client.groupMember.upsert({
        where: { groupId_userId: { groupId, userId }, tenantId },
        create: { tenantId, groupId, userId, addedByUserId },
        update: {},
        include: memberInclude,
      }),
    async removeMember({ tenantId, groupId, userId }, client = db) {
      return (await client.groupMember.deleteMany({ where: { tenantId, groupId, userId } })).count;
    },
  });
}
