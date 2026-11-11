import { toPrismaPaging } from "../../../lib/query.js";

const USER_SELECT = { select: { id: true, email: true, name: true } };
const SORT = {
  name: (d) => ({ membership: { user: { name: d } } }),
  email: (d) => ({ membership: { user: { email: d } } }),
  createdAt: (d) => ({ createdAt: d }),
};

/** @param {{ db: any }} deps */
export function createWorkspaceMemberRepository({ db }) {
  const include = { membership: { include: { user: USER_SELECT } } };
  return Object.freeze({
    async list({ tenantId, workspaceId, q, sort, page, pageSize }) {
      const where = {
        tenantId,
        workspaceId,
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
        db.workspaceMember.findMany({
          where,
          include,
          orderBy: sort.map(({ field, direction }) => SORT[field](direction)),
          ...toPrismaPaging({ page, pageSize }),
        }),
        db.workspaceMember.count({ where }),
      ]);
      return { items, totalItems };
    },
    findActiveMembership: ({ tenantId, userId }, client = db) =>
      client.tenantMembership.findFirst({
        where: { tenantId, userId, status: "active" },
        select: { id: true },
      }),
    async upsert({ tenantId, workspaceId, userId, addedByUserId }, client = db) {
      return client.workspaceMember.upsert({
        where: { workspaceId_userId: { workspaceId, userId } },
        create: { tenantId, workspaceId, userId, addedByUserId, status: "active" },
        update: { status: "active" },
        include,
      });
    },
    async remove({ tenantId, workspaceId, userId }, client = db) {
      return (await client.workspaceMember.deleteMany({ where: { tenantId, workspaceId, userId } }))
        .count;
    },
    /** A workspace member who is removed also loses their direct workspace-scope role assignments there. */
    async revokeWorkspaceAssignments({ tenantId, workspaceId, userId }, client = db) {
      return (
        await client.userRoleAssignment.deleteMany({
          where: { tenantId, workspaceId, userId, scopeType: "workspace" },
        })
      ).count;
    },
  });
}
