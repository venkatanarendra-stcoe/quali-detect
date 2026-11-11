import { toPrismaOrderBy, toPrismaPaging } from "../../../lib/query.js";

const CURRENT_SUBSCRIPTION = (now) => ({
  status: { in: ["trial", "active"] },
  startsAt: { lte: now },
  OR: [{ endsAt: null }, { endsAt: { gt: now } }],
});
const PLAN_INCLUDE = { planVersion: { include: { plan: { select: { key: true, name: true } } } } };
const LIFECYCLE_ACTIONS = [
  "tenant.created",
  "tenant.suspended",
  "tenant.reactivated",
  "tenant.deactivated",
  "tenant.restored",
];

/**
 * Platform view of tenants: METADATA AND COUNTS only (docs/AUTHORIZATION.md §5.5 `platform.tenant.view`). It never reads
 * tenant content (findings, repositories, audit logs of the tenant). Every query names its tenant ids explicitly.
 * `client` is the Prisma client or a transaction client.
 * @param {{ db: any, authzRepository: { findTenantAdministratorIds: Function } }} deps
 */
export function createPlatformTenantRepository({ db, authzRepository }) {
  const countBy = async (model, field, tenantIds, where = {}) => {
    const rows = await db[model].groupBy({
      by: ["tenantId", ...(field ? [field] : [])],
      where: { tenantId: { in: tenantIds }, ...where },
      _count: { _all: true },
    });
    return rows;
  };
  return Object.freeze({
    async list({ q, status, plan, sort, page, pageSize, now }) {
      const where = {
        ...(status ? { status } : {}),
        ...(q
          ? {
              OR: [
                { name: { contains: q, mode: "insensitive" } },
                { slug: { contains: q, mode: "insensitive" } },
              ],
            }
          : {}),
        ...(plan
          ? {
              subscriptions: {
                some: { ...CURRENT_SUBSCRIPTION(now), planVersion: { plan: { key: plan } } },
              },
            }
          : {}),
      };
      const [tenants, totalItems] = await Promise.all([
        db.tenant.findMany({
          where,
          orderBy: toPrismaOrderBy(sort),
          ...toPrismaPaging({ page, pageSize }),
        }),
        db.tenant.count({ where }),
      ]);
      const ids = tenants.map((t) => t.id);
      if (ids.length === 0) return { items: [], totalItems };
      const [users, workspaces, subscriptions] = await Promise.all([
        countBy("tenantMembership", null, ids, { status: "active" }),
        countBy("workspace", null, ids, { status: "active" }),
        db.tenantSubscription.findMany({
          where: { tenantId: { in: ids }, ...CURRENT_SUBSCRIPTION(now) },
          include: PLAN_INCLUDE,
          orderBy: { startsAt: "desc" },
        }),
      ]);
      const count = (rows, id) => rows.find((r) => r.tenantId === id)?._count._all ?? 0;
      return {
        items: tenants.map((tenant) => ({
          tenant,
          userCount: count(users, tenant.id),
          workspaceCount: count(workspaces, tenant.id),
          subscription: subscriptions.find((s) => s.tenantId === tenant.id) ?? null,
        })),
        totalItems,
      };
    },
    findById: (id, client = db) => client.tenant.findUnique({ where: { id } }),
    async detailAggregates(tenantId, now) {
      const [memberships, workspaces, groups, subscription] = await Promise.all([
        db.tenantMembership.groupBy({
          by: ["status"],
          where: { tenantId },
          _count: { _all: true },
        }),
        db.workspace.groupBy({ by: ["status"], where: { tenantId }, _count: { _all: true } }),
        db.group.count({ where: { tenantId } }),
        db.tenantSubscription.findFirst({
          where: { tenantId, ...CURRENT_SUBSCRIPTION(now) },
          include: PLAN_INCLUDE,
          orderBy: { startsAt: "desc" },
        }),
      ]);
      const by = (rows, key) => rows.find((r) => r.status === key)?._count._all ?? 0;
      return {
        users: {
          active: by(memberships, "active"),
          invited: by(memberships, "invited"),
          suspended: by(memberships, "suspended"),
        },
        workspaces: { active: by(workspaces, "active"), archived: by(workspaces, "archived") },
        groups,
        subscription,
      };
    },
    /** Users who currently hold the tenant-administration capability (active membership). */
    async findAdministrators(tenantId, now) {
      const ids = [...(await authzRepository.findTenantAdministratorIds({ tenantId, now }))];
      return ids.length === 0
        ? []
        : db.user.findMany({
            where: { id: { in: ids } },
            select: { id: true, name: true, email: true },
            orderBy: { name: "asc" },
          });
    },
    /** Invited users already holding an administrator assignment (the provisioned first admin before acceptance). */
    async findPendingAdministrators(tenantId) {
      const roles = await db.role.findMany({
        where: {
          OR: [{ tenantId: null }, { tenantId }],
          AND: [
            { permissions: { some: { permissionKey: "role.manage" } } },
            { permissions: { some: { permissionKey: "role_assignment.manage_tenant" } } },
          ],
        },
        select: { id: true },
      });
      if (roles.length === 0) return [];
      const rows = await db.userRoleAssignment.findMany({
        where: {
          tenantId,
          scopeType: "tenant",
          roleId: { in: roles.map((r) => r.id) },
          membership: { status: "invited" },
        },
        include: { membership: { include: { user: { select: { id: true, email: true } } } } },
      });
      return rows.map((r) => r.membership.user);
    },
    lifecycleEvents: (tenantId, limit = 20) =>
      db.platformAuditLog.findMany({
        where: { tenantId, action: { in: LIFECYCLE_ACTIONS } },
        include: { actor: { select: { name: true } } },
        orderBy: { createdAt: "desc" },
        take: limit,
      }),
    listPublishedPlanVersions: () =>
      db.planVersion.findMany({
        where: { status: "published", plan: { status: "active" } },
        include: { plan: { select: { key: true, name: true } } },
        orderBy: [{ plan: { name: "asc" } }, { version: "desc" }],
      }),
    findPublishedPlanVersion: (id, client = db) =>
      client.planVersion.findFirst({
        where: { id, status: "published", plan: { status: "active" } },
        include: { plan: { select: { key: true, name: true } } },
      }),
    createTenant: (data, client = db) => client.tenant.create({ data }),
    createSubscription: (data, client = db) => client.tenantSubscription.create({ data }),
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
    /** Finds the global user by email or creates it; an existing user is never modified. */
    upsertUser: ({ email, name }, client = db) =>
      client.user.upsert({
        where: { email },
        create: { email, name, status: "active" },
        update: {},
      }),
    createInvitedMembership: ({ tenantId, userId }, client = db) =>
      client.tenantMembership.create({ data: { tenantId, userId, status: "invited" } }),
    createTenantAssignment: ({ tenantId, userId, roleId }, client = db) =>
      client.userRoleAssignment.create({
        data: { tenantId, userId, roleId, scopeType: "tenant", scopeKey: "tenant" },
      }),
    /** Moves a tenant between statuses only from the allowed current ones. @returns {Promise<number>} rows changed */
    async transition({ id, from, to, deactivatedAt }, client = db) {
      return (
        await client.tenant.updateMany({
          where: { id, status: { in: from } },
          data: { status: to, ...(deactivatedAt !== undefined ? { deactivatedAt } : {}) },
        })
      ).count;
    },
    hasTrialSubscription: async (tenantId, now, client = db) =>
      (await client.tenantSubscription.count({
        where: { tenantId, status: "trial", ...CURRENT_SUBSCRIPTION(now) },
      })) > 0,
    transaction: (fn) => db.$transaction(fn),
  });
}
