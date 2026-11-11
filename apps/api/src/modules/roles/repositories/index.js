import { toPrismaOrderBy, toPrismaPaging } from "../../../lib/query.js";

const include = {
  permissions: { select: { permissionKey: true } },
  _count: { select: { userAssignments: true, groupAssignments: true } },
};

/**
 * Data access for roles. Roles visible to a tenant: built-in (no tenant) and its own custom roles. Mutations only ever
 * match the tenant's own rows.
 * @param {{ db: any }} deps
 */
export function createRoleRepository({ db }) {
  const visible = (tenantId) => ({ OR: [{ tenantId: null }, { tenantId }] });
  return Object.freeze({
    async list({ tenantId, kind, q, sort, page, pageSize }) {
      const where = {
        ...visible(tenantId),
        ...(kind ? { kind } : {}),
        ...(q ? { name: { contains: q, mode: "insensitive" } } : {}),
      };
      const [items, totalItems] = await Promise.all([
        db.role.findMany({
          where,
          include,
          orderBy: toPrismaOrderBy(sort),
          ...toPrismaPaging({ page, pageSize }),
        }),
        db.role.count({ where }),
      ]);
      return { items, totalItems };
    },
    findVisible: ({ tenantId, id }, client = db) =>
      client.role.findFirst({ where: { id, ...visible(tenantId) }, include }),
    create: ({ tenantId, createdByUserId, key, name, description, permissionKeys }, client = db) =>
      client.role.create({
        data: {
          tenantId,
          ownerKey: tenantId,
          key,
          name,
          description,
          kind: "custom",
          createdByUserId,
          permissions: {
            create: permissionKeys.map((permissionKey) => ({ permissionKey, tenantId })),
          },
        },
        include,
      }),
    async update({ tenantId, id, data, permissionKeys }, client = db) {
      const result = await client.role.updateMany({ where: { id, tenantId }, data });
      if (result.count === 0) return null;
      if (permissionKeys) {
        await client.rolePermission.deleteMany({ where: { roleId: id } });
        await client.rolePermission.createMany({
          data: permissionKeys.map((permissionKey) => ({ roleId: id, permissionKey, tenantId })),
        });
      }
      return client.role.findFirst({ where: { id, tenantId }, include });
    },
    async countAssignments({ tenantId, roleId }, client = db) {
      const [users, groups] = await Promise.all([
        client.userRoleAssignment.count({ where: { tenantId, roleId } }),
        client.groupRoleAssignment.count({ where: { tenantId, roleId } }),
      ]);
      return users + groups;
    },
    async delete({ tenantId, id }, client = db) {
      return (await client.role.deleteMany({ where: { id, tenantId } })).count;
    },
    /** Whether the user currently holds the role (directly or through a group); used for the no-self-escalation rule. */
    async userHoldsRole({ tenantId, userId, roleId, now }, client = db) {
      const live = { status: "active", OR: [{ expiresAt: null }, { expiresAt: { gt: now } }] };
      const [direct, viaGroup] = await Promise.all([
        client.userRoleAssignment.count({ where: { tenantId, userId, roleId, ...live } }),
        client.groupRoleAssignment.count({
          where: { tenantId, roleId, ...live, group: { members: { some: { userId } } } },
        }),
      ]);
      return direct + viaGroup > 0;
    },
  });
}
