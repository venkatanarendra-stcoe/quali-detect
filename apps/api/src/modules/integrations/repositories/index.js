/**
 * Data access for GitHub installations, tenant links, workspace links and their allow-lists (SPEC §18, ADR-012).
 * Installations are platform-level facts (no tenant). EVERY other function takes the tenantId (and the workspaceId where
 * the row is workspace-owned) and puts it in the `where`, including compound-unique upserts and updates. `client` is the
 * Prisma client or a transaction client. Never exposes tokens (none are stored).
 * @param {{ db: any }} deps
 */
export function createIntegrationRepository({ db }) {
  const tenantLinkInclude = {
    installation: true,
    workspaceLinks: {
      where: { status: "linked" },
      select: { id: true, workspaceId: true, workspace: { select: { name: true } } },
    },
  };
  const workspaceLinkInclude = { link: { include: { installation: true } } };

  return Object.freeze({
    transaction: (fn) => db.$transaction(fn),

    // ---- Installations (platform facts)
    findInstallationByExternalId: (externalInstallationId, client = db) =>
      client.scmInstallation.findUnique({
        where: { provider_externalInstallationId: { provider: "github", externalInstallationId } },
      }),
    upsertInstallation: (data, client = db) =>
      client.scmInstallation.upsert({
        where: {
          provider_externalInstallationId: {
            provider: "github",
            externalInstallationId: data.externalInstallationId,
          },
        },
        create: { provider: "github", ...data, lastCheckedAt: new Date() },
        update: { ...data, lastCheckedAt: new Date() },
      }),
    markInstallationRevoked: (installationId, client = db) =>
      client.scmInstallation.update({
        where: { id: installationId },
        data: { status: "revoked", lastCheckedAt: new Date() },
      }),

    // ---- Tenant installation links (exclusivity across tenants is the partial unique index; this read is the only
    // deliberately tenant-less lookup: "who holds this installation")
    findLinkedByInstallation: (installationId, client = db) =>
      client.scmInstallationLink.findFirst({ where: { installationId, status: "linked" } }),
    findTenantLinkForInstallation: ({ tenantId, installationId }, client = db) =>
      client.scmInstallationLink.findUnique({
        where: { tenantId_installationId: { tenantId, installationId } },
      }),
    createLink: (data, client = db) => client.scmInstallationLink.create({ data }),
    reactivateLink: ({ tenantId, id, linkedByUserId }, client = db) =>
      client.scmInstallationLink.update({
        where: { id, tenantId },
        data: {
          status: "linked",
          linkedByUserId,
          linkedAt: new Date(),
          unlinkedAt: null,
          unlinkedByUserId: null,
        },
      }),
    findTenantLink: ({ tenantId, linkId }, client = db) =>
      client.scmInstallationLink.findFirst({
        where: { id: linkId, tenantId },
        include: tenantLinkInclude,
      }),
    listTenantLinks: ({ tenantId }, client = db) =>
      client.scmInstallationLink.findMany({
        where: { tenantId },
        include: tenantLinkInclude,
        orderBy: { linkedAt: "asc" },
      }),

    // ---- Workspace links
    findWorkspace: ({ tenantId, workspaceId }, client = db) =>
      client.workspace.findFirst({
        where: { tenantId, id: workspaceId },
        select: { id: true, name: true, status: true },
      }),
    findWorkspaceLink: ({ tenantId, workspaceId, workspaceLinkId }, client = db) =>
      client.scmWorkspaceLink.findFirst({
        where: { id: workspaceLinkId, tenantId, workspaceId },
        include: workspaceLinkInclude,
      }),
    findWorkspaceLinkForPair: ({ tenantId, workspaceId, linkId }, client = db) =>
      client.scmWorkspaceLink.findFirst({
        where: { tenantId, workspaceId, linkId },
        include: workspaceLinkInclude,
      }),
    listWorkspaceLinks: ({ tenantId, workspaceId }, client = db) =>
      client.scmWorkspaceLink.findMany({
        where: { tenantId, workspaceId, status: "linked" },
        include: workspaceLinkInclude,
        orderBy: { linkedAt: "asc" },
      }),
    createWorkspaceLink: ({ tenantId, workspaceId, linkId, linkedByUserId }, client = db) =>
      client.scmWorkspaceLink.create({
        data: { tenantId, workspaceId, linkId, linkedByUserId },
      }),
    reactivateWorkspaceLink: ({ tenantId, workspaceId, id, linkedByUserId }, client = db) =>
      client.scmWorkspaceLink.updateMany({
        where: { id, tenantId, workspaceId },
        data: {
          status: "linked",
          linkedByUserId,
          linkedAt: new Date(),
          unlinkedAt: null,
          unlinkedByUserId: null,
        },
      }),
    unlinkWorkspaceLink: ({ tenantId, workspaceId, id, userId }, client = db) =>
      client.scmWorkspaceLink.updateMany({
        where: { id, tenantId, workspaceId },
        data: { status: "unlinked", unlinkedAt: new Date(), unlinkedByUserId: userId },
      }),

    /** Per workspace link: live repositories, unavailable ones, allow-list size and last event time. */
    async workspaceLinkStats({ tenantId, workspaceId, workspaceLinkIds }, client = db) {
      const [rows, allow, last] = await Promise.all([
        client.repository.groupBy({
          by: ["workspaceLinkId", "status"],
          where: {
            tenantId,
            workspaceId,
            workspaceLinkId: { in: workspaceLinkIds },
            status: { not: "disconnected" },
          },
          _count: { _all: true },
        }),
        client.scmWorkspaceLinkRepository.groupBy({
          by: ["workspaceLinkId"],
          where: { tenantId, workspaceLinkId: { in: workspaceLinkIds } },
          _count: { _all: true },
        }),
        client.repository.groupBy({
          by: ["workspaceLinkId"],
          where: { tenantId, workspaceId, workspaceLinkId: { in: workspaceLinkIds } },
          _max: { lastEventAt: true },
        }),
      ]);
      const stats = new Map(
        workspaceLinkIds.map((id) => [
          id,
          {
            repositoryCount: 0,
            unavailableRepositoryCount: 0,
            allowListCount: 0,
            lastEventAt: null,
          },
        ]),
      );
      for (const row of rows) {
        const s = stats.get(row.workspaceLinkId);
        s.repositoryCount += row._count._all;
        if (row.status === "unavailable") s.unavailableRepositoryCount += row._count._all;
      }
      for (const row of allow) stats.get(row.workspaceLinkId).allowListCount = row._count._all;
      for (const row of last) stats.get(row.workspaceLinkId).lastEventAt = row._max.lastEventAt;
      return stats;
    },

    /** Per tenant link: live and unavailable repositories (all workspaces of the tenant). */
    async tenantLinkCounts({ tenantId, linkIds }, client = db) {
      const rows = await client.repository.groupBy({
        by: ["linkId", "status"],
        where: { tenantId, linkId: { in: linkIds }, status: { not: "disconnected" } },
        _count: { _all: true },
      });
      const counts = new Map(
        linkIds.map((id) => [id, { repositoryCount: 0, unavailableRepositoryCount: 0 }]),
      );
      for (const row of rows) {
        const c = counts.get(row.linkId);
        c.repositoryCount += row._count._all;
        if (row.status === "unavailable") c.unavailableRepositoryCount += row._count._all;
      }
      return counts;
    },

    // ---- Repositories of one workspace link (workspace unlink and re-link)
    /** Disconnects (never deletes) the workspace link's live repositories. Returns the affected rows for events and audit. */
    async disconnectWorkspaceRepositories(
      { tenantId, workspaceId, workspaceLinkId, reason },
      client = db,
    ) {
      const rows = await client.repository.findMany({
        where: { tenantId, workspaceId, workspaceLinkId, status: { not: "disconnected" } },
        select: {
          id: true,
          workspaceId: true,
          provider: true,
          fullName: true,
          externalRepoId: true,
        },
      });
      if (rows.length > 0)
        await client.repository.updateMany({
          where: { tenantId, workspaceId, workspaceLinkId, id: { in: rows.map((r) => r.id) } },
          data: { status: "disconnected", disconnectedAt: new Date(), disconnectReason: reason },
        });
      return rows;
    },
    /**
     * Repositories of this workspace that an unlink or an uninstall disconnected (same rows, same ids). Other disconnect
     * reasons (for example `repo_inaccessible`) are never restored automatically: they need an explicit Connect.
     */
    findRestorableRepositories({ tenantId, workspaceId }, client = db) {
      return client.repository.findMany({
        where: {
          tenantId,
          workspaceId,
          status: "disconnected",
          disconnectReason: {
            in: ["installation_revoked", "workspace_unlinked", "installation_unlinked"],
          },
        },
        select: {
          id: true,
          workspaceId: true,
          fullName: true,
          externalRepoId: true,
          nodeId: true,
          defaultBranch: true,
          disconnectReason: true,
        },
      });
    },
    restoreRepositories({ tenantId, workspaceId, linkId, workspaceLinkId, ids }, client = db) {
      return client.repository.updateMany({
        where: { tenantId, workspaceId, id: { in: ids }, status: "disconnected" },
        data: {
          status: "active",
          linkId,
          workspaceLinkId,
          disconnectedAt: null,
          disconnectReason: null,
          consecutiveSyncFailures: 0,
          lastSyncError: null,
        },
      });
    },
    /** External ids among `externalRepoIds` that are connected (live) in this workspace link. */
    async findLiveExternalIds(
      { tenantId, workspaceId, workspaceLinkId, externalRepoIds },
      client = db,
    ) {
      const rows = await client.repository.findMany({
        where: {
          tenantId,
          workspaceId,
          workspaceLinkId,
          externalRepoId: { in: externalRepoIds },
          status: { not: "disconnected" },
        },
        select: { externalRepoId: true },
      });
      return new Set(rows.map((r) => r.externalRepoId));
    },

    // ---- Allow-list
    listAllowList: ({ tenantId, workspaceLinkId }, client = db) =>
      client.scmWorkspaceLinkRepository.findMany({
        where: { tenantId, workspaceLinkId },
        orderBy: { fullName: "asc" },
      }),
    /**
     * External ids that are on the allow-list of a link of ANOTHER workspace of the tenant (a repository serves one
     * workspace). With `workspaceId`, stale entries of the same workspace's earlier links (for example after a re-install)
     * do not count: they are moved to the new link.
     */
    async findAllowedElsewhere(
      { tenantId, workspaceId, workspaceLinkId, externalRepoIds },
      client = db,
    ) {
      const rows = await client.scmWorkspaceLinkRepository.findMany({
        where: {
          tenantId,
          provider: "github",
          externalRepoId: { in: externalRepoIds },
          workspaceLinkId: { not: workspaceLinkId },
          ...(workspaceId ? { workspaceLink: { workspaceId: { not: workspaceId } } } : {}),
        },
        select: { externalRepoId: true },
      });
      return new Set(rows.map((r) => r.externalRepoId));
    },
    /** External ids on the allow-list of ANY link of this workspace (current or earlier). */
    async findWorkspaceAllowListIds({ tenantId, workspaceId, externalRepoIds }, client = db) {
      const rows = await client.scmWorkspaceLinkRepository.findMany({
        where: {
          tenantId,
          provider: "github",
          externalRepoId: { in: externalRepoIds },
          workspaceLink: { workspaceId },
        },
        select: { externalRepoId: true },
      });
      return new Set(rows.map((r) => r.externalRepoId));
    },
    /** Removes this workspace's entries for these repositories that sit on its EARLIER links (they move to the new link). */
    removeStaleAllowListEntries(
      { tenantId, workspaceId, workspaceLinkId, externalRepoIds },
      client = db,
    ) {
      return client.scmWorkspaceLinkRepository.deleteMany({
        where: {
          tenantId,
          provider: "github",
          externalRepoId: { in: externalRepoIds },
          workspaceLinkId: { not: workspaceLinkId },
          workspaceLink: { workspaceId },
        },
      });
    },
    addAllowListEntries: ({ tenantId, workspaceLinkId, entries, userId }, client = db) =>
      client.scmWorkspaceLinkRepository.createMany({
        data: entries.map((e) => ({
          tenantId,
          workspaceLinkId,
          provider: "github",
          externalRepoId: e.externalRepoId,
          nodeId: e.nodeId ?? null,
          fullName: e.fullName,
          addedByUserId: userId,
        })),
      }),
    removeAllowListEntries: ({ tenantId, workspaceLinkId, externalRepoIds }, client = db) =>
      client.scmWorkspaceLinkRepository.deleteMany({
        where: { tenantId, workspaceLinkId, externalRepoId: { in: externalRepoIds } },
      }),
    clearAllowList: ({ tenantId, workspaceLinkId }, client = db) =>
      client.scmWorkspaceLinkRepository.deleteMany({ where: { tenantId, workspaceLinkId } }),

    // ---- Tenant setting
    findSettings: ({ tenantId }, client = db) =>
      client.tenantIntegrationSettings.findFirst({ where: { tenantId } }),
    upsertSettings: ({ tenantId, allowWorkspaceLinking, userId }, client = db) =>
      client.tenantIntegrationSettings.upsert({
        where: { tenantId },
        create: { tenantId, allowWorkspaceLinking, updatedByUserId: userId },
        update: { allowWorkspaceLinking, updatedByUserId: userId },
      }),

    // ---- Deliveries (installation-level webhook health)
    async listDeliveries({ tenantId, externalInstallationId, page, pageSize }) {
      const where = { tenantId, externalInstallationId };
      const [items, totalItems] = await Promise.all([
        db.scmWebhookDelivery.findMany({
          where,
          orderBy: { receivedAt: "desc" },
          skip: (page - 1) * pageSize,
          take: pageSize,
        }),
        db.scmWebhookDelivery.count({ where }),
      ]);
      return { items, totalItems };
    },
  });
}
