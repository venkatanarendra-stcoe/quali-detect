/** Health shown in the UI, derived from status and the failure counter (SPEC §7.2). */
export function healthOf(repository) {
  if (repository.status === "disconnected") return "disconnected";
  if (repository.status === "unavailable") return "error";
  return repository.consecutiveSyncFailures > 0 ? "degraded" : "healthy";
}

/** Repository DTO. Never a Prisma model; carries no token and no installation numbers. @param {any} r */
export const toRepositoryDto = (r) => ({
  id: r.id,
  workspaceId: r.workspaceId,
  linkId: r.linkId,
  workspaceLinkId: r.workspaceLinkId,
  provider: r.provider,
  externalRepoId: r.externalRepoId,
  fullName: r.fullName,
  name: r.name,
  ownerLogin: r.ownerLogin,
  htmlUrl: r.htmlUrl,
  visibility: r.visibility,
  defaultBranch: r.defaultBranch,
  description: r.description,
  displayName: r.displayName,
  ownerUserId: r.ownerUserId,
  status: r.status,
  enabled: r.enabled,
  archived: r.archived,
  health: healthOf(r),
  healthReason: r.lastSyncError,
  consecutiveSyncFailures: r.consecutiveSyncFailures,
  lastSyncedAt: r.lastSyncedAt,
  lastEventAt: r.lastEventAt,
  connectedAt: r.connectedAt,
  disconnectedAt: r.disconnectedAt,
  disconnectReason: r.disconnectReason,
  pipelineCount: 0, // the pipelines module will provide the real count
});
