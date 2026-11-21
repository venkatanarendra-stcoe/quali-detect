/** Health shown in the UI, derived from status and the failure counter (SPEC §7.2). */
export function healthOf(repository) {
  if (repository.status === "disconnected") return "disconnected";
  if (repository.status === "unavailable") return "error";
  return repository.consecutiveSyncFailures > 0 ? "degraded" : "healthy";
}

/** Repository DTO. Never a Prisma model; carries no token and no installation numbers. @param {any} r @param {number} [pipelineCount] non-deleted pipelines (from the pipelines module) */
export const toRepositoryDto = (r, pipelineCount = 0) => ({
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
  pipelineCount,
});

/**
 * The file name of the SBOM download: built from the repository's full name with every character outside `[A-Za-z0-9._-]` turned
 * into `-` (so no quote, slash, control character, non-ASCII text or header injection can reach `Content-Disposition`), cut to 80
 * characters, never starting with a dot or a hyphen; a name that leaves nothing becomes `repository`.
 * @param {string | null | undefined} fullName
 * @returns {string} e.g. `acme-payments-service-sbom.cdx.json`
 */
export function sbomFileName(fullName) {
  const base = String(fullName ?? "")
    .replace(/[^A-Za-z0-9._-]+/g, "-")
    .replace(/^[.-]+/, "")
    .slice(0, 80)
    .replace(/[.-]+$/, "");
  return `${base || "repository"}-sbom.cdx.json`;
}
