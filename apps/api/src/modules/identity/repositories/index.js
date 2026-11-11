const TENANT_SELECT = { id: true, slug: true, name: true, status: true };

/**
 * Data access of the identity module. Memberships are read for the signed-in user (global user -> own memberships);
 * everything tenant-owned carries an explicit tenantId.
 * @param {{ db: any }} deps
 */
export function createIdentityRepository({ db }) {
  const tenantsOf = async (userId, status) => {
    const rows = await db.tenantMembership.findMany({
      where: { userId, status },
      include: { tenant: { select: TENANT_SELECT } },
    });
    return rows.map((m) => m.tenant).sort((a, b) => a.name.localeCompare(b.name));
  };
  return Object.freeze({
    /** Tenants where the user has an active membership. @param {{ userId: string }} input */
    listActiveTenants: ({ userId }) => tenantsOf(userId, "active"),
    /** Tenants that invited the user and wait for acceptance. @param {{ userId: string }} input */
    listInvitedTenants: ({ userId }) => tenantsOf(userId, "invited"),
    /** @param {{ tenantId: string, userId: string }} input */
    findActiveMembership: ({ tenantId, userId }) =>
      db.tenantMembership.findFirst({
        where: { tenantId, userId, status: "active" },
        select: { id: true, status: true, joinedAt: true },
      }),
    /** @param {{ userId: string, tenantId: string }} input */
    async findInvitedTenant({ userId, tenantId }) {
      const row = await db.tenantMembership.findFirst({
        where: { userId, tenantId, status: "invited" },
        include: { tenant: { select: TENANT_SELECT } },
      });
      return row?.tenant ?? null;
    },
    /** @param {{ userId: string, tenantId: string, at: Date }} input @returns {Promise<number>} rows changed */
    async acceptInvitation({ userId, tenantId, at }, client = db) {
      const result = await client.tenantMembership.updateMany({
        where: { tenantId, userId, status: "invited" },
        data: { status: "active", joinedAt: at },
      });
      return result.count;
    },
    transaction: (fn) => db.$transaction(fn),
    /** @param {{ tenantId: string }} input */
    findTenant: ({ tenantId }) =>
      db.tenant.findUnique({ where: { id: tenantId }, select: TENANT_SELECT }),
    /** @param {{ userId: string, at: Date }} input */
    touchLastLogin: ({ userId, at }) =>
      db.user.update({ where: { id: userId }, data: { lastLoginAt: at } }),
    /** @param {{ userId: string }} input */
    findUser: ({ userId }) =>
      db.user.findUnique({
        where: { id: userId },
        select: { id: true, email: true, name: true, status: true },
      }),
  });
}
