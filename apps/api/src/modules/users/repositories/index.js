import { toPrismaPaging } from "../../../lib/query.js";

const SORT = {
  name: (d) => ({ user: { name: d } }),
  email: (d) => ({ user: { email: d } }),
  status: (d) => ({ status: d }),
  createdAt: (d) => ({ createdAt: d }),
};
const include = {
  user: { select: { id: true, email: true, name: true, lastLoginAt: true, status: true } },
};

/**
 * Tenant view of users = memberships. Every query carries the tenantId; the global `users` table is only touched to
 * create the person behind an invitation.
 * @param {{ db: any }} deps
 */
export function createUserRepository({ db }) {
  return Object.freeze({
    async list({ tenantId, status, q, sort, page, pageSize }) {
      const where = {
        tenantId,
        status: status ?? { not: "removed" },
        ...(q
          ? {
              user: {
                OR: [
                  { name: { contains: q, mode: "insensitive" } },
                  { email: { contains: q, mode: "insensitive" } },
                ],
              },
            }
          : {}),
      };
      const [items, totalItems] = await Promise.all([
        db.tenantMembership.findMany({
          where,
          include,
          orderBy: sort.map(({ field, direction }) => SORT[field](direction)),
          ...toPrismaPaging({ page, pageSize }),
        }),
        db.tenantMembership.count({ where }),
      ]);
      return { items, totalItems };
    },
    findMembership: ({ tenantId, userId }, client = db) =>
      client.tenantMembership.findFirst({ where: { tenantId, userId }, include }),
    /** Memberships that occupy a seat: invited, active and suspended. */
    countSeats: ({ tenantId }, client = db) =>
      client.tenantMembership.count({
        where: { tenantId, status: { in: ["invited", "active", "suspended"] } },
      }),
    lockSeats: (tenantId, client) =>
      client.$executeRaw`SELECT pg_advisory_xact_lock(hashtext(${`limit:users:${tenantId}`}))`,
    /** Finds the global user by email or creates it; an existing user is never modified. */
    upsertUser: ({ email, name }, client = db) =>
      client.user.upsert({
        where: { email },
        create: { email, name, status: "active" },
        update: {},
      }),
    async invite({ tenantId, userId, invitedByUserId }, client = db) {
      return client.tenantMembership.upsert({
        where: { tenantId_userId: { tenantId, userId } },
        create: { tenantId, userId, status: "invited", invitedByUserId },
        update: { status: "invited", invitedByUserId, joinedAt: null },
        include,
      });
    },
    /** Moves a membership between statuses only from the allowed current ones. @returns {Promise<number>} rows changed */
    async transition({ tenantId, userId, from, to }, client = db) {
      return (
        await client.tenantMembership.updateMany({
          where: { tenantId, userId, status: { in: from } },
          data: { status: to },
        })
      ).count;
    },
    /**
     * Ends a membership: marks it removed and deletes everything it granted in this tenant (assignments, group and
     * workspace membership) so re-inviting later does not resurrect old access; detaches live sessions from the tenant.
     */
    async removeMembership({ tenantId, userId }, client = db) {
      await client.userRoleAssignment.deleteMany({ where: { tenantId, userId } });
      await client.groupMember.deleteMany({ where: { tenantId, userId } });
      await client.workspaceMember.deleteMany({ where: { tenantId, userId } });
      await client.session.updateMany({
        where: { userId, activeTenantId: tenantId, revokedAt: null },
        data: { activeTenantId: null },
      });
      return (
        await client.tenantMembership.updateMany({
          where: { tenantId, userId, status: { not: "removed" } },
          data: { status: "removed" },
        })
      ).count;
    },
  });
}
