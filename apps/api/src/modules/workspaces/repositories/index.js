import { WORKSPACE_INCLUDE as include } from "../../../lib/workspace-include.js";
import { toPrismaOrderBy, toPrismaPaging } from "../../../lib/query.js";

/**
 * Data access for workspaces. Every query carries the tenantId; `client` is the Prisma client or a transaction client.
 * @param {{ db: any }} deps
 */
export function createWorkspaceRepository({ db }) {
  return Object.freeze({
    /** Only workspaces in `visibleIds` (the caller's visible set) are ever returned. */
    async list({ tenantId, visibleIds, status, q, sort, page, pageSize }) {
      const where = {
        tenantId,
        id: { in: visibleIds },
        ...(status ? { status } : {}),
        ...(q ? { name: { contains: q, mode: "insensitive" } } : {}),
      };
      const [items, totalItems] = await Promise.all([
        db.workspace.findMany({
          where,
          include,
          orderBy: toPrismaOrderBy(sort),
          ...toPrismaPaging({ page, pageSize }),
        }),
        db.workspace.count({ where }),
      ]);
      return { items, totalItems };
    },
    /** Number of non-archived workspaces of the tenant among `visibleIds` (the id filter is never dropped). */
    countVisibleActive: ({ tenantId, visibleIds }, client = db) =>
      client.workspace.count({ where: { tenantId, id: { in: visibleIds }, status: "active" } }),
    findById: ({ tenantId, id }, client = db) =>
      client.workspace.findFirst({ where: { tenantId, id }, include }),
    countActive: ({ tenantId }, client = db) =>
      client.workspace.count({ where: { tenantId, status: "active" } }),
    /** Serializes workspace creation/restoration of one tenant so the plan limit cannot be overshot. */
    lockLimit: (tenantId, client) =>
      client.$executeRaw`SELECT pg_advisory_xact_lock(hashtext(${`limit:workspaces:${tenantId}`}))`,
    findActiveMembership: ({ tenantId, userId }, client = db) =>
      client.tenantMembership.findFirst({
        where: { tenantId, userId, status: "active" },
        select: { id: true },
      }),
    create: ({ tenantId, data }, client = db) =>
      client.workspace.create({ data: { ...data, tenantId }, include }),
    async update({ tenantId, id, data }, client = db) {
      const result = await client.workspace.updateMany({ where: { tenantId, id }, data });
      return result.count === 0
        ? null
        : client.workspace.findFirst({ where: { tenantId, id }, include });
    },
    ensureMember: ({ tenantId, workspaceId, userId, addedByUserId }, client = db) =>
      client.workspaceMember.upsert({
        where: { workspaceId_userId: { workspaceId, userId }, tenantId },
        create: { tenantId, workspaceId, userId, addedByUserId, status: "active" },
        update: { status: "active" },
      }),
    /**
     * The built-in role that holds ALL of `permissionKeys` (a capability, not a role name). If several qualify, the one
     * with the fewest permissions wins (least privilege), then the key, so the choice is deterministic.
     * @param {readonly string[]} permissionKeys
     */
    findBuiltInRoleWithCapability: async (permissionKeys, client = db) => {
      const candidates = await client.role.findMany({
        where: {
          ownerKey: "built-in",
          AND: permissionKeys.map((permissionKey) => ({
            permissions: { some: { permissionKey } },
          })),
        },
        select: { id: true, key: true, _count: { select: { permissions: true } } },
      });
      candidates.sort(
        (a, b) => a._count.permissions - b._count.permissions || a.key.localeCompare(b.key),
      );
      return candidates[0] ? { id: candidates[0].id } : null;
    },
    /** Gives `userId` the role at workspace scope (idempotent). */
    ensureWorkspaceAssignment: (
      { tenantId, workspaceId, userId, roleId, createdByUserId },
      client = db,
    ) =>
      client.userRoleAssignment.upsert({
        where: {
          tenantId_userId_roleId_scopeKey: { tenantId, userId, roleId, scopeKey: workspaceId },
        },
        create: {
          tenantId,
          userId,
          roleId,
          scopeType: "workspace",
          workspaceId,
          scopeKey: workspaceId,
          createdByUserId,
        },
        update: { status: "active", expiresAt: null },
      }),
    transaction: (fn) => db.$transaction(fn),
  });
}
