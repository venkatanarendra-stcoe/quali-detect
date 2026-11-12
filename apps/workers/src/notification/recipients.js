/**
 * Recipient lookup of the notification worker. Every query carries the tenantId; the tenant comes from the message that the
 * worker's ownership verifier already validated, never from a payload field. Holders are people with an ACTIVE, unexpired
 * assignment (direct or through a group) of a role that carries the permission key, whose membership and account are active
 * (the same rules as the API's authorization engine).
 * @param {{ db: any, now?: () => Date }} deps
 */
export function createRecipientFinder({ db, now = () => new Date() }) {
  const live = (at) => ({ status: "active", OR: [{ expiresAt: null }, { expiresAt: { gt: at } }] });

  /**
   * Who holds `permissionKey` in each of `workspaceIds` (workspace-scope key): a tenant-scope assignment covers every
   * workspace, a workspace-scope assignment only its own.
   * @returns {Promise<Map<string, Set<string>>>} userId -> workspace ids
   */
  async function workspaceHolders({ tenantId, permissionKey, workspaceIds }) {
    const holders = new Map();
    if (workspaceIds.length === 0) return holders;
    const at = now();
    const roles = await db.role.findMany({
      where: {
        OR: [{ tenantId: null }, { tenantId }],
        permissions: { some: { permissionKey } },
      },
      select: { id: true },
    });
    if (roles.length === 0) return holders;
    const base = {
      tenantId,
      roleId: { in: roles.map((r) => r.id) },
      status: "active",
      AND: [
        {
          OR: [
            { scopeType: "tenant" },
            { scopeType: "workspace", workspaceId: { in: workspaceIds } },
          ],
        },
        { OR: live(at).OR },
      ],
    };
    const [direct, viaGroups] = await Promise.all([
      db.userRoleAssignment.findMany({
        where: base,
        select: { userId: true, scopeType: true, workspaceId: true },
      }),
      db.groupRoleAssignment.findMany({
        where: base,
        select: { groupId: true, scopeType: true, workspaceId: true },
      }),
    ]);
    const add = (userId, a) => {
      const set = holders.get(userId) ?? new Set();
      if (a.scopeType === "tenant") for (const id of workspaceIds) set.add(id);
      else set.add(a.workspaceId);
      holders.set(userId, set);
    };
    for (const a of direct) add(a.userId, a);
    if (viaGroups.length > 0) {
      const members = await db.groupMember.findMany({
        where: { tenantId, groupId: { in: [...new Set(viaGroups.map((g) => g.groupId))] } },
        select: { userId: true, groupId: true },
      });
      for (const g of viaGroups)
        for (const m of members) if (m.groupId === g.groupId) add(m.userId, g);
    }
    return keepActive(tenantId, holders);
  }

  /** Who holds a tenant-scope `permissionKey` (tenant-scope assignments only). @returns {Promise<Set<string>>} */
  async function tenantHolders({ tenantId, permissionKey }) {
    const at = now();
    const roles = await db.role.findMany({
      where: { OR: [{ tenantId: null }, { tenantId }], permissions: { some: { permissionKey } } },
      select: { id: true },
    });
    if (roles.length === 0) return new Set();
    const base = {
      tenantId,
      roleId: { in: roles.map((r) => r.id) },
      scopeType: "tenant",
      ...live(at),
    };
    const [direct, viaGroups] = await Promise.all([
      db.userRoleAssignment.findMany({ where: base, select: { userId: true } }),
      db.groupRoleAssignment.findMany({ where: base, select: { groupId: true } }),
    ]);
    const ids = new Set(direct.map((a) => a.userId));
    if (viaGroups.length > 0) {
      const members = await db.groupMember.findMany({
        where: { tenantId, groupId: { in: viaGroups.map((g) => g.groupId) } },
        select: { userId: true },
      });
      for (const m of members) ids.add(m.userId);
    }
    const active = await keepActive(tenantId, new Map([...ids].map((id) => [id, null])));
    return new Set(active.keys());
  }

  /** Drops people whose membership in the tenant or account is not active. */
  async function keepActive(tenantId, byUser) {
    if (byUser.size === 0) return byUser;
    const rows = await db.tenantMembership.findMany({
      where: {
        tenantId,
        status: "active",
        userId: { in: [...byUser.keys()] },
        user: { status: "active" },
      },
      select: { userId: true },
    });
    const ok = new Set(rows.map((r) => r.userId));
    return new Map([...byUser].filter(([id]) => ok.has(id)));
  }

  return Object.freeze({
    /**
     * Recipients of an installation uninstall/suspension (SPEC §18.6 A6): active holders of tenant `integration.manage` and,
     * per affected workspace, active holders of `workspace_integration.manage` there. ONE entry per person, listing the
     * affected workspaces that person can see (holds `workspace.view` in); a tenant-level manager is told about every
     * affected workspace they can see.
     * @param {{ tenantId: string, workspaceIds: string[] }} input
     * @returns {Promise<Array<{ userId: string, tenantLevel: boolean, workspaceIds: string[] }>>}
     */
    async forInstallationRevoked({ tenantId, workspaceIds }) {
      const [tenantManagers, workspaceManagers, viewers] = await Promise.all([
        tenantHolders({ tenantId, permissionKey: "integration.manage" }),
        workspaceHolders({ tenantId, permissionKey: "workspace_integration.manage", workspaceIds }),
        workspaceHolders({ tenantId, permissionKey: "workspace.view", workspaceIds }),
      ]);
      const everyone = new Set([...tenantManagers, ...workspaceManagers.keys()]);
      const recipients = [];
      for (const userId of everyone) {
        const tenantLevel = tenantManagers.has(userId);
        const wanted = tenantLevel
          ? new Set(workspaceIds)
          : (workspaceManagers.get(userId) ?? new Set());
        const visible = viewers.get(userId) ?? new Set();
        recipients.push({
          userId,
          tenantLevel,
          workspaceIds: workspaceIds.filter((id) => wanted.has(id) && visible.has(id)),
        });
      }
      return recipients.sort((a, b) => a.userId.localeCompare(b.userId));
    },
  });
}
