/**
 * Data access for webhook ingestion. The only tenant source is the installation LINK (installation -> the single linked
 * tenant); repositories are always found with that tenantId. Nothing here reads a tenant from a payload.
 * @param {{ db: any }} deps
 */
export function createWebhookRepository({ db }) {
  return Object.freeze({
    transaction: (fn) => db.$transaction(fn),
    async findLinkByExternalInstallation(externalInstallationId) {
      const installation = await db.scmInstallation.findUnique({
        where: { provider_externalInstallationId: { provider: "github", externalInstallationId } },
        include: { links: { where: { status: "linked" }, take: 1 } },
      });
      const link = installation?.links[0];
      return link
        ? {
            linkId: link.id,
            tenantId: link.tenantId,
            installationId: installation.id,
            installationStatus: installation.status,
          }
        : null;
    },
    findTenantStatus: (tenantId) =>
      db.tenant.findUnique({ where: { id: tenantId }, select: { status: true } }),
    findRepository: ({ tenantId, externalRepoId }, client = db) =>
      client.repository.findUnique({
        where: {
          tenantId_provider_externalRepoId: { tenantId, provider: "github", externalRepoId },
        },
        select: { id: true, workspaceId: true, status: true, enabled: true },
      }),
    /** Inserts the delivery row; a unique violation means the delivery was already seen. */
    createDelivery: (data, client = db) => client.scmWebhookDelivery.create({ data }),
    markDelivery: ({ deliveryId, outcome, tenantId }, client = db) =>
      client.scmWebhookDelivery.update({
        where: { provider_deliveryId: { provider: "github", deliveryId } },
        data: { outcome, ...(tenantId ? { tenantId } : {}) },
      }),
    createEvent: (data, client = db) => client.scmEvent.create({ data }),
    touchRepository: ({ tenantId, id }, client = db) =>
      client.repository.updateMany({ where: { id, tenantId }, data: { lastEventAt: new Date() } }),
  });
}
