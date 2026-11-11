/**
 * Reads the data the central engine needs. Every query carries an explicit tenantId. `client` is the Prisma client or a
 * transaction client.
 * @param {{ db: any }} deps
 */
export function createAuthzRepository({ db }) {
  const roleInclude = {
    role: { select: { id: true, name: true, permissions: { select: { permissionKey: true } } } },
  };
  const live = (now) => ({
    status: "active",
    OR: [{ expiresAt: null }, { expiresAt: { gt: now } }],
  });
  const toInput = (subjectType, subjectField) => (a) => ({
    id: a.id,
    roleId: a.role.id,
    roleName: a.role.name,
    tenantId: a.tenantId,
    subjectType,
    subjectId: a[subjectField],
    scopeType: a.scopeType,
    workspaceId: a.workspaceId,
    status: a.status,
    expiresAt: a.expiresAt,
    permissionKeys: a.role.permissions.map((p) => p.permissionKey),
  });
  return Object.freeze({
    /** @param {{ tenantId: string, userId: string }} input */
    findGroupIds: async ({ tenantId, userId }, client = db) =>
      (
        await client.groupMember.findMany({
          where: { tenantId, userId },
          select: { groupId: true },
        })
      ).map((g) => g.groupId),
    /** Active, unexpired direct and group assignments for a user (group ids come from flat memberships). */
    async findAssignments({ tenantId, userId, groupIds, now }, client = db) {
      const [direct, viaGroups] = await Promise.all([
        client.userRoleAssignment.findMany({
          where: { tenantId, userId, ...live(now) },
          include: roleInclude,
        }),
        groupIds.length === 0
          ? []
          : client.groupRoleAssignment.findMany({
              where: { tenantId, groupId: { in: groupIds }, ...live(now) },
              include: roleInclude,
            }),
      ]);
      return [
        ...direct.map(toInput("user", "userId")),
        ...viaGroups.map(toInput("group", "groupId")),
      ];
    },
    /** @param {{ tenantId: string }} input */
    listWorkspaces: ({ tenantId }, client = db) =>
      client.workspace.findMany({
        where: { tenantId },
        select: { id: true, tenantId: true, name: true, status: true },
      }),
    /**
     * User ids that currently hold the tenant-administration capability (role.manage AND role_assignment.manage_tenant at
     * tenant scope) with an active membership, directly or through a group.
     * @param {{ tenantId: string, now: Date }} input
     * @returns {Promise<Set<string>>}
     */
    async findTenantAdministratorIds({ tenantId, now }, client = db) {
      const roles = await client.role.findMany({
        where: {
          OR: [{ tenantId: null }, { tenantId }],
          AND: [
            { permissions: { some: { permissionKey: "role.manage" } } },
            { permissions: { some: { permissionKey: "role_assignment.manage_tenant" } } },
          ],
        },
        select: { id: true },
      });
      if (roles.length === 0) return new Set();
      const roleIds = roles.map((r) => r.id);
      const where = { tenantId, roleId: { in: roleIds }, scopeType: "tenant", ...live(now) };
      const [direct, viaGroups] = await Promise.all([
        client.userRoleAssignment.findMany({ where, select: { userId: true } }),
        client.groupRoleAssignment.findMany({ where, select: { groupId: true } }),
      ]);
      const userIds = new Set(direct.map((a) => a.userId));
      if (viaGroups.length > 0) {
        const members = await client.groupMember.findMany({
          where: { tenantId, groupId: { in: viaGroups.map((g) => g.groupId) } },
          select: { userId: true },
        });
        for (const m of members) userIds.add(m.userId);
      }
      if (userIds.size === 0) return userIds;
      const active = await client.tenantMembership.findMany({
        where: {
          tenantId,
          status: "active",
          userId: { in: [...userIds] },
          user: { status: "active" },
        },
        select: { userId: true },
      });
      return new Set(active.map((m) => m.userId));
    },
    /**
     * Active, unexpired workspace-scope assignments in a workspace that carry `workspace.manage_members` (a workspace
     * administrator): user assignments with an active membership, group assignments of non-empty groups.
     * @param {{ tenantId: string, workspaceId: string, now: Date }} input
     * @returns {Promise<number>}
     */
    async countWorkspaceAdministratorAssignments({ tenantId, workspaceId, now }, client = db) {
      const roles = await client.role.findMany({
        where: {
          OR: [{ tenantId: null }, { tenantId }],
          permissions: { some: { permissionKey: "workspace.manage_members" } },
        },
        select: { id: true },
      });
      if (roles.length === 0) return 0;
      const where = {
        tenantId,
        workspaceId,
        scopeType: "workspace",
        roleId: { in: roles.map((r) => r.id) },
        ...live(now),
      };
      const [users, groups] = await Promise.all([
        client.userRoleAssignment.count({ where: { ...where, membership: { status: "active" } } }),
        client.groupRoleAssignment.count({ where: { ...where, group: { members: { some: {} } } } }),
      ]);
      return users + groups;
    },
    /** @param {string} key */
    lockWorkspaceAdministrators: (tenantId, workspaceId, client) =>
      client.$executeRaw`SELECT pg_advisory_xact_lock(hashtext(${`workspace-admins:${tenantId}:${workspaceId}`}))`,
    /** Serializes administrator-affecting changes of one tenant (released at commit). @param {string} tenantId */
    lockTenantAdministrators: (tenantId, client) =>
      client.$executeRaw`SELECT pg_advisory_xact_lock(hashtext(${`tenant-admins:${tenantId}`}))`,
    /** Runs `fn(tx)` in one database transaction. */
    transaction: (fn, options) => db.$transaction(fn, options),
  });
}
