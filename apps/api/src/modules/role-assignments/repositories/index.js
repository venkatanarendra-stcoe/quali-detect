import { toPrismaOrderBy } from "../../../lib/query.js";

const ROLE = {
  select: {
    id: true,
    key: true,
    name: true,
    kind: true,
    permissions: { select: { permissionKey: true } },
  },
};
const INCLUDE = {
  user: {
    role: ROLE,
    membership: { include: { user: { select: { id: true, email: true, name: true } } } },
  },
  group: { role: ROLE, group: { select: { id: true, name: true } } },
};
const TABLE = { user: "userRoleAssignment", group: "groupRoleAssignment" };
const compare = (a, b, { field, direction }) => {
  const x = a[field]?.getTime?.() ?? null;
  const y = b[field]?.getTime?.() ?? null;
  if (x === y) return 0;
  if (x === null) return 1; // no expiry sorts last
  if (y === null) return -1;
  return direction === "desc" ? y - x : x - y;
};

/**
 * Data access for role assignments, kept in two tables (users and groups). Every query carries tenantId and, for
 * workspace scope, the workspaceId; an id from another tenant or scope matches nothing.
 * @param {{ db: any }} deps
 */
export function createRoleAssignmentRepository({ db }) {
  const scopeWhere = ({ tenantId, scopeType, workspaceId }) => ({
    tenantId,
    scopeType,
    ...(scopeType === "workspace" ? { workspaceId } : {}),
  });
  return Object.freeze({
    /** Both subject types merged (newest/soonest first as sorted); each table is capped at the page end before merging. */
    async list({
      tenantId,
      scopeType,
      workspaceId,
      subjectType,
      subjectId,
      roleId,
      status,
      sort,
      page,
      pageSize,
    }) {
      const kinds = subjectType ? [subjectType] : ["user", "group"];
      const where = (kind) => ({
        ...scopeWhere({ tenantId, scopeType, workspaceId }),
        ...(roleId ? { roleId } : {}),
        ...(status ? { status } : {}),
        ...(subjectId ? { [kind === "user" ? "userId" : "groupId"]: subjectId } : {}),
      });
      const parts = await Promise.all(
        kinds.map(async (kind) => {
          const [rows, total] = await Promise.all([
            db[TABLE[kind]].findMany({
              where: where(kind),
              include: INCLUDE[kind],
              orderBy: toPrismaOrderBy(sort),
              take: page * pageSize,
            }),
            db[TABLE[kind]].count({ where: where(kind) }),
          ]);
          return { kind, rows, total };
        }),
      );
      const merged = parts.flatMap(({ kind, rows }) => rows.map((row) => ({ kind, row })));
      merged.sort((a, b) => {
        for (const s of sort) {
          const c = compare(a.row, b.row, s);
          if (c !== 0) return c;
        }
        return 0;
      });
      return {
        items: merged.slice((page - 1) * pageSize, page * pageSize),
        totalItems: parts.reduce((n, p) => n + p.total, 0),
      };
    },
    /** Finds an assignment in either table, within the tenant and scope. @returns {Promise<{ kind: "user" | "group", row: any } | null>} */
    async findById({ tenantId, scopeType, workspaceId, id }, client = db) {
      for (const kind of ["user", "group"]) {
        const row = await client[TABLE[kind]].findFirst({
          where: { id, ...scopeWhere({ tenantId, scopeType, workspaceId }) },
          include: INCLUDE[kind],
        });
        if (row) return { kind, row };
      }
      return null;
    },
    findVisibleRole: ({ tenantId, id }, client = db) =>
      client.role.findFirst({
        where: { id, OR: [{ tenantId: null }, { tenantId }] },
        include: { permissions: { select: { permissionKey: true } } },
      }),
    findActiveMembership: ({ tenantId, userId }, client = db) =>
      client.tenantMembership.findFirst({
        where: { tenantId, userId, status: "active" },
        select: { id: true },
      }),
    findGroup: ({ tenantId, id }, client = db) =>
      client.group.findFirst({ where: { tenantId, id }, select: { id: true } }),
    isGroupMember: ({ tenantId, groupId, userId }, client = db) =>
      client.groupMember.count({ where: { tenantId, groupId, userId } }).then((n) => n > 0),
    ensureWorkspaceMember: ({ tenantId, workspaceId, userId, addedByUserId }, client = db) =>
      client.workspaceMember.upsert({
        where: { workspaceId_userId: { workspaceId, userId }, tenantId },
        create: { tenantId, workspaceId, userId, addedByUserId, status: "active" },
        update: {},
      }),
    create: (
      { kind, tenantId, subjectId, roleId, scopeType, workspaceId, expiresAt, createdByUserId },
      client = db,
    ) =>
      client[TABLE[kind]].create({
        data: {
          tenantId,
          [kind === "user" ? "userId" : "groupId"]: subjectId,
          roleId,
          scopeType,
          workspaceId: scopeType === "workspace" ? workspaceId : null,
          scopeKey: scopeType === "workspace" ? workspaceId : "tenant",
          expiresAt,
          createdByUserId,
        },
        include: INCLUDE[kind],
      }),
    async update({ kind, tenantId, id, data }, client = db) {
      await client[TABLE[kind]].updateMany({ where: { id, tenantId }, data });
      return client[TABLE[kind]].findFirst({ where: { id, tenantId }, include: INCLUDE[kind] });
    },
    async delete({ kind, tenantId, id }, client = db) {
      return (await client[TABLE[kind]].deleteMany({ where: { id, tenantId } })).count;
    },
  });
}
