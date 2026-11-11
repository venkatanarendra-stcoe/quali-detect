/** Health of a link, derived from the installation state and its repositories. */
function healthOf(link, unavailableRepositoryCount) {
  if (link.status !== "linked") return "unlinked";
  if (link.installation.status === "revoked") return "revoked";
  if (link.installation.status === "suspended") return "suspended";
  return unavailableRepositoryCount > 0 ? "degraded" : "healthy";
}

/**
 * Link DTO. It contains no token and no secret; `externalInstallationId` is shown to tenant administrators only (the route
 * needs integration.view, held by administrators by default).
 * @param {any} link link with its installation
 * @param {{ repositoryCount: number, unavailableRepositoryCount: number, workspaceIds: string[] }} extra
 */
export const toLinkDto = (link, { repositoryCount, unavailableRepositoryCount, workspaceIds }) => ({
  id: link.id,
  provider: link.installation.provider,
  status: link.status,
  health: healthOf(link, unavailableRepositoryCount),
  account: { login: link.installation.accountLogin, type: link.installation.accountType },
  externalInstallationId: link.installation.externalInstallationId,
  repositorySelection: link.installation.repositorySelection,
  permissions: link.installation.permissions ?? {},
  linkedAt: link.linkedAt,
  linkedByUserId: link.linkedByUserId,
  repositoryCount,
  unavailableRepositoryCount,
  workspaceScope: workspaceIds,
});

export const toDeliveryDto = (row) => ({
  id: row.id,
  receivedAt: row.receivedAt,
  event: row.eventType,
  action: row.action,
  outcome: row.outcome,
  signatureVerified: true,
});
