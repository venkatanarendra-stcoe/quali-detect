/**
 * Data access for GitHub installations and tenant links. Installations are platform-level facts (no tenant); every link
 * query carries the tenantId. Never exposes tokens (none are stored).
 * @param {{ db: any }} deps
 */
export function createIntegrationRepository({ db }) {
  const linkInclude = { installation: true, workspaces: { select: { workspaceId: true } } };
  return Object.freeze({
    transaction: (fn) => db.$transaction(fn),

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
    findLinkedByInstallation: (installationId, client = db) =>
      client.scmInstallationLink.findFirst({ where: { installationId, status: "linked" } }),
    findTenantLinkForInstallation: ({ tenantId, installationId }, client = db) =>
      client.scmInstallationLink.findUnique({
        where: { tenantId_installationId: { tenantId, installationId } },
      }),
    createLink: (data, client = db) => client.scmInstallationLink.create({ data }),
    reactivateLink: ({ id, linkedByUserId }, client = db) =>
      client.scmInstallationLink.update({
        where: { id },
        data: {
          status: "linked",
          linkedByUserId,
          linkedAt: new Date(),
          unlinkedAt: null,
          unlinkedByUserId: null,
        },
      }),
    /** Re-link restores the repositories that an unlink disconnected (same rows, same ids). */
    restoreRepositories: ({ tenantId, linkId }, client = db) =>
      client.repository.updateMany({
        where: {
          tenantId,
          linkId,
          status: "disconnected",
          disconnectReason: "installation_unlinked",
        },
        data: {
          status: "active",
          disconnectedAt: null,
          disconnectReason: null,
          consecutiveSyncFailures: 0,
        },
      }),
    findLink: ({ tenantId, linkId }, client = db) =>
      client.scmInstallationLink.findFirst({
        where: { id: linkId, tenantId },
        include: linkInclude,
      }),
    listLinks: ({ tenantId }, client = db) =>
      client.scmInstallationLink.findMany({
        where: { tenantId },
        include: linkInclude,
        orderBy: { linkedAt: "asc" },
      }),
    async repositoryCounts({ tenantId, linkIds }, client = db) {
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
    unlink: ({ tenantId, linkId, userId }, client = db) =>
      client.scmInstallationLink.updateMany({
        where: { id: linkId, tenantId },
        data: { status: "unlinked", unlinkedAt: new Date(), unlinkedByUserId: userId },
      }),
    /** Disconnects (never deletes) the link's live repositories. Returns the affected rows for events and audit. */
    async disconnectRepositories({ tenantId, linkId, reason }, client = db) {
      const rows = await client.repository.findMany({
        where: { tenantId, linkId, status: { not: "disconnected" } },
        select: { id: true, workspaceId: true, provider: true, fullName: true },
      });
      if (rows.length > 0)
        await client.repository.updateMany({
          where: { tenantId, id: { in: rows.map((r) => r.id) } },
          data: { status: "disconnected", disconnectedAt: new Date(), disconnectReason: reason },
        });
      return rows;
    },
    /** Linked connections of the tenant with their organization scope and this workspace's own setting. */
    listWorkspaceLinks: ({ tenantId, workspaceId }, client = db) =>
      client.scmInstallationLink.findMany({
        where: { tenantId, status: "linked" },
        include: {
          installation: true,
          workspaces: { select: { workspaceId: true } },
          workspaceSettings: { where: { tenantId, workspaceId } },
        },
        orderBy: { linkedAt: "asc" },
      }),
    findWorkspaceLink: ({ tenantId, workspaceId, linkId }, client = db) =>
      client.scmInstallationLink.findFirst({
        where: { id: linkId, tenantId, status: "linked" },
        include: {
          installation: true,
          workspaces: { select: { workspaceId: true } },
          workspaceSettings: { where: { tenantId, workspaceId } },
        },
      }),
    upsertWorkspaceSetting: ({ tenantId, workspaceId, linkId, enabled, userId }, client = db) =>
      client.scmWorkspaceLinkSetting.upsert({
        where: { workspaceId_linkId: { workspaceId, linkId } },
        create: { tenantId, workspaceId, linkId, enabled, updatedByUserId: userId },
        update: { enabled, updatedByUserId: userId },
      }),
    async countWorkspaces({ tenantId, workspaceIds }, client = db) {
      return client.workspace.count({ where: { tenantId, id: { in: workspaceIds } } });
    },
    async setScope({ tenantId, linkId, workspaceIds }, client = db) {
      await client.scmInstallationLinkWorkspace.deleteMany({ where: { tenantId, linkId } });
      if (workspaceIds.length > 0)
        await client.scmInstallationLinkWorkspace.createMany({
          data: workspaceIds.map((workspaceId) => ({ tenantId, linkId, workspaceId })),
        });
    },
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
