import { toPrismaOrderBy, toPrismaPaging } from "../../../lib/query.js";

/**
 * Data access for repositories. EVERY query carries the tenantId (and workspace ids where listing); a repository is never
 * read by id alone. `client` is the Prisma client or a transaction client.
 * @param {{ db: any }} deps
 */
export function createRepositoryRepository({ db }) {
  return Object.freeze({
    transaction: (fn) => db.$transaction(fn),
    async list({
      tenantId,
      workspaceIds,
      workspaceId,
      provider,
      status,
      health,
      q,
      sort,
      page,
      pageSize,
    }) {
      const healthWhere = {
        healthy: { status: "active", consecutiveSyncFailures: 0 },
        degraded: { status: "active", consecutiveSyncFailures: { gt: 0 } },
        error: { status: "unavailable" },
        disconnected: { status: "disconnected" },
      }[health];
      const where = {
        tenantId,
        workspaceId: workspaceId
          ? { in: workspaceIds.filter((id) => id === workspaceId) }
          : { in: workspaceIds },
        ...(provider ? { provider } : {}),
        ...(status ? { status } : {}),
        ...(healthWhere ?? {}),
        ...(q
          ? {
              OR: [
                { fullName: { contains: q, mode: "insensitive" } },
                { displayName: { contains: q, mode: "insensitive" } },
              ],
            }
          : {}),
      };
      const [items, totalItems] = await Promise.all([
        db.repository.findMany({
          where,
          orderBy: toPrismaOrderBy(sort),
          ...toPrismaPaging({ page, pageSize }),
        }),
        db.repository.count({ where }),
      ]);
      return { items, totalItems };
    },
    findById: ({ tenantId, id }, client = db) =>
      client.repository.findFirst({ where: { tenantId, id } }),
    findByExternalId: ({ tenantId, externalRepoId }, client = db) =>
      client.repository.findUnique({
        where: {
          tenantId_provider_externalRepoId: { tenantId, provider: "github", externalRepoId },
        },
      }),
    async findManyExternal({ tenantId, externalRepoIds }, client = db) {
      return client.repository.findMany({
        where: {
          tenantId,
          provider: "github",
          externalRepoId: { in: externalRepoIds },
          status: { not: "disconnected" },
        },
        select: { externalRepoId: true },
      });
    },
    countLive: ({ tenantId }, client) =>
      client.repository.count({ where: { tenantId, status: { not: "disconnected" } } }),
    lockLimit: (tenantId, client) =>
      client.$executeRaw`SELECT pg_advisory_xact_lock(hashtext(${`limit:repositories:${tenantId}`}))`,
    /** The tenant's installation link (for live reads of a connected repository). */
    findLink: ({ tenantId, linkId }, client = db) =>
      client.scmInstallationLink.findFirst({
        where: { id: linkId, tenantId },
        include: { installation: true },
      }),
    /** A workspace link, only when it belongs to this tenant AND this workspace (foreign ids are not found). */
    findWorkspaceLink: ({ tenantId, workspaceId, workspaceLinkId }, client = db) =>
      client.scmWorkspaceLink.findFirst({
        where: { id: workspaceLinkId, tenantId, workspaceId },
        include: { link: { include: { installation: true } } },
      }),
    /** The allow-list entries of a workspace link among `externalRepoIds`. */
    findAllowListEntries: ({ tenantId, workspaceLinkId, externalRepoIds }, client = db) =>
      client.scmWorkspaceLinkRepository.findMany({
        where: { tenantId, workspaceLinkId, externalRepoId: { in: externalRepoIds } },
        select: { externalRepoId: true, fullName: true },
      }),
    listAllowList: ({ tenantId, workspaceLinkId }, client = db) =>
      client.scmWorkspaceLinkRepository.findMany({
        where: { tenantId, workspaceLinkId },
        select: { externalRepoId: true },
      }),
    findWorkspace: ({ tenantId, id }, client = db) =>
      client.workspace.findFirst({ where: { tenantId, id }, select: { id: true, status: true } }),
    findActiveMembership: ({ tenantId, userId }, client = db) =>
      client.tenantMembership.findFirst({
        where: { tenantId, userId, status: "active" },
        select: { id: true },
      }),
    create: (data, client = db) => client.repository.create({ data }),
    update: ({ tenantId, id, data }, client = db) =>
      client.repository.updateMany({ where: { id, tenantId }, data }),
  });
}
