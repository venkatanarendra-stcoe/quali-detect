/** Health of a link, derived from the installation state and its repositories. */
function healthOf(status, installationStatus, unavailableRepositoryCount) {
  if (status !== "linked") return "unlinked";
  if (installationStatus === "revoked") return "revoked";
  if (installationStatus === "suspended") return "suspended";
  return unavailableRepositoryCount > 0 ? "degraded" : "healthy";
}

/**
 * Tenant-level installation row (T-13/T-14, read-only). It contains no token and no secret. `workspaces` lists ONLY the
 * workspaces the caller can see (id and name); the others are only counted (`hiddenWorkspaceCount`).
 * @param {any} link tenant link with installation and its linked workspace links
 * @param {{ repositoryCount: number, unavailableRepositoryCount: number }} counts
 * @param {Set<string>} visibleWorkspaceIds workspaces the caller can see
 */
export function toInstallationDto(link, counts, visibleWorkspaceIds) {
  const workspaces = [];
  let hidden = 0;
  for (const wl of link.workspaceLinks) {
    if (visibleWorkspaceIds.has(wl.workspaceId))
      workspaces.push({ id: wl.workspaceId, name: wl.workspace.name });
    else hidden += 1;
  }
  return {
    id: link.id,
    provider: link.installation.provider,
    status: link.status,
    health: healthOf(link.status, link.installation.status, counts.unavailableRepositoryCount),
    account: { login: link.installation.accountLogin, type: link.installation.accountType },
    externalInstallationId: link.installation.externalInstallationId,
    repositorySelection: link.installation.repositorySelection,
    permissions: link.installation.permissions ?? {},
    linkedAt: link.linkedAt,
    linkedByUserId: link.linkedByUserId,
    repositoryCount: counts.repositoryCount,
    unavailableRepositoryCount: counts.unavailableRepositoryCount,
    workspaceCount: link.workspaceLinks.length,
    workspaces: workspaces.sort((a, b) => a.name.localeCompare(b.name)),
    hiddenWorkspaceCount: hidden,
  };
}

export const toDeliveryDto = (row) => ({
  id: row.id,
  receivedAt: row.receivedAt,
  event: row.eventType,
  action: row.action,
  outcome: row.outcome,
  signatureVerified: true,
});

/**
 * Workspace view of a link (T-42): the workspace's own connection to a GitHub installation. No installation number and no
 * permissions; counts are this workspace's only.
 * @param {any} wl workspace link with its tenant link and installation
 * @param {{ repositoryCount: number, unavailableRepositoryCount: number, allowListCount: number, lastEventAt: Date | null }} stats
 */
export const toWorkspaceLinkDto = (wl, stats) => ({
  id: wl.id,
  workspaceId: wl.workspaceId,
  installationLinkId: wl.linkId,
  provider: wl.link.installation.provider,
  status: wl.status,
  health: healthOf(wl.status, wl.link.installation.status, stats.unavailableRepositoryCount),
  account: { login: wl.link.installation.accountLogin, type: wl.link.installation.accountType },
  repositorySelection: wl.link.installation.repositorySelection,
  linkedAt: wl.linkedAt,
  linkedByUserId: wl.linkedByUserId,
  repositoryCount: stats.repositoryCount,
  unavailableRepositoryCount: stats.unavailableRepositoryCount,
  allowListCount: stats.allowListCount,
  lastEventAt: stats.lastEventAt,
});

/** One installation repository as the allow-list picker shows it. */
export const toAllowListItemDto = (remote, { allowed, allowedElsewhere, connected }) => ({
  externalRepoId: remote.externalRepoId,
  fullName: remote.fullName,
  visibility: remote.visibility,
  defaultBranch: remote.defaultBranch,
  archived: remote.archived,
  allowed,
  allowedElsewhere,
  connected,
});

export const toSettingsDto = (row) => ({
  allowWorkspaceLinking: row?.allowWorkspaceLinking ?? true,
  updatedAt: row?.updatedAt ?? null,
  updatedByUserId: row?.updatedByUserId ?? null,
});
