/**
 * Restore rule for disconnected repositories (SPEC §18.7), shared by the API (a workspace links an installation) and the SCM
 * event consumer of the workers (an installation gains access to repositories), so the rule exists exactly once.
 *
 * Every function is TENANT-scoped and WORKSPACE-scoped: the tenant comes from the trusted caller context (a session or a
 * validated job), never from a payload. They take a Prisma client or transaction as first argument.
 */

/** Reasons a repository is restored automatically; every other reason (for example `repo_inaccessible`) needs an explicit Connect. */
export const RESTORABLE_DISCONNECT_REASONS = Object.freeze([
  "installation_revoked",
  "workspace_unlinked",
  "installation_unlinked",
]);

/**
 * Disconnected repositories of ONE workspace whose reason allows an automatic restore.
 * @param {any} client Prisma client or transaction
 * @param {{ tenantId: string, workspaceId: string }} scope
 */
export function findRestorableRepositories(client, { tenantId, workspaceId }) {
  return client.repository.findMany({
    where: {
      tenantId,
      workspaceId,
      status: "disconnected",
      disconnectReason: { in: [...RESTORABLE_DISCONNECT_REASONS] },
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
}

/**
 * Sets the given disconnected repositories of the workspace back to `active` on the given links (same rows, ids unchanged).
 * @param {any} client
 * @param {{ tenantId: string, workspaceId: string, linkId: string, workspaceLinkId: string, ids: string[] }} input
 */
export function restoreRepositories(
  client,
  { tenantId, workspaceId, linkId, workspaceLinkId, ids },
) {
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
}

/**
 * External ids on the allow-list of ANY link of this workspace (current or earlier).
 * @param {any} client
 * @param {{ tenantId: string, workspaceId: string, externalRepoIds: string[] }} input
 * @returns {Promise<Set<string>>}
 */
export async function findWorkspaceAllowListIds(
  client,
  { tenantId, workspaceId, externalRepoIds },
) {
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
}

/**
 * External ids on the allow-list of a link of ANOTHER workspace of the tenant (a repository serves one workspace). With
 * `workspaceId`, entries of the same workspace's earlier links do not count: they move to the new link.
 * @param {any} client
 * @param {{ tenantId: string, workspaceId?: string, workspaceLinkId: string, externalRepoIds: string[] }} input
 * @returns {Promise<Set<string>>}
 */
export async function findAllowedElsewhere(
  client,
  { tenantId, workspaceId, workspaceLinkId, externalRepoIds },
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
}

/**
 * Removes this workspace's entries for these repositories that sit on its EARLIER links (they move to the new link).
 * @param {any} client
 * @param {{ tenantId: string, workspaceId: string, workspaceLinkId: string, externalRepoIds: string[] }} input
 */
export function removeStaleAllowListEntries(
  client,
  { tenantId, workspaceId, workspaceLinkId, externalRepoIds },
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
}

/**
 * The restore rule. Restores to `active`, in the same row, the repositories of THIS workspace that were disconnected by an
 * unlink (`workspace_unlinked`, `installation_unlinked`) or an uninstall (`installation_revoked`), matched by tenant +
 * provider + external repo id, that the installation can access (`accessibleExternalIds`), and, after an uninstall, that are
 * still on this workspace's allow-list. Any other reason stays disconnected. Other workspaces and other tenants are never
 * touched, and a repository another workspace has since put on its own list is skipped. The restored repositories move to
 * the given links and to the given workspace link's allow-list. Auditing and announcing are left to the caller, which knows
 * the actor.
 * @param {any} client Prisma transaction client (the caller owns the transaction)
 * @param {{
 *   tenantId: string, workspaceId: string, workspaceLinkId: string, tenantLinkId: string,
 *   userId: string, accessibleExternalIds: Set<string> | string[]
 * }} input `userId` is recorded as the person who added the allow-list entries
 * @returns {Promise<Array<{ id: string, workspaceId: string, fullName: string, externalRepoId: string, nodeId: string | null, defaultBranch: string | null, disconnectReason: string | null }>>} the restored rows (state before the restore)
 */
export async function restoreWorkspaceRepositories(
  client,
  { tenantId, workspaceId, workspaceLinkId, tenantLinkId, userId, accessibleExternalIds },
) {
  const accessible = new Set(accessibleExternalIds);
  const scope = { tenantId, workspaceId };
  const candidates = (await findRestorableRepositories(client, scope)).filter((r) =>
    accessible.has(r.externalRepoId),
  );
  if (candidates.length === 0) return [];
  const listed = await findWorkspaceAllowListIds(client, {
    ...scope,
    externalRepoIds: candidates.map((r) => r.externalRepoId),
  });
  const eligible = candidates.filter(
    (r) => r.disconnectReason !== "installation_revoked" || listed.has(r.externalRepoId),
  );
  if (eligible.length === 0) return [];
  const elsewhere = await findAllowedElsewhere(client, {
    ...scope,
    workspaceLinkId,
    externalRepoIds: eligible.map((r) => r.externalRepoId),
  });
  const restorable = eligible.filter((r) => !elsewhere.has(r.externalRepoId));
  if (restorable.length === 0) return [];
  // Compare-and-set per row (the WHERE requires `disconnected`): only rows THIS call restored are returned, so a concurrent
  // or repeated restore audits and announces nothing twice.
  const restored = [];
  for (const r of restorable) {
    const { count } = await restoreRepositories(client, {
      ...scope,
      linkId: tenantLinkId,
      workspaceLinkId,
      ids: [r.id],
    });
    if (count === 1) restored.push(r);
  }
  if (restored.length === 0) return [];
  const externalRepoIds = restored.map((r) => r.externalRepoId);
  await removeStaleAllowListEntries(client, { ...scope, workspaceLinkId, externalRepoIds });
  await client.scmWorkspaceLinkRepository.deleteMany({
    where: { tenantId, workspaceLinkId, externalRepoId: { in: externalRepoIds } },
  });
  await client.scmWorkspaceLinkRepository.createMany({
    data: restored.map((r) => ({
      tenantId,
      workspaceLinkId,
      provider: "github",
      externalRepoId: r.externalRepoId,
      nodeId: r.nodeId ?? null,
      fullName: r.fullName,
      addedByUserId: userId,
    })),
  });
  return restored;
}

/**
 * The same functions bound to a Prisma client, in the `(input, client = db)` style of the module repositories. Used by the
 * API's repository (for `findAllowedElsewhere`) and by the data-access checks.
 * @param {{ db: any }} deps
 */
export function createScmRestoreRepository({ db }) {
  return Object.freeze({
    findRestorableRepositories: (input, client = db) => findRestorableRepositories(client, input),
    restoreRepositories: (input, client = db) => restoreRepositories(client, input),
    findWorkspaceAllowListIds: (input, client = db) => findWorkspaceAllowListIds(client, input),
    findAllowedElsewhere: (input, client = db) => findAllowedElsewhere(client, input),
    removeStaleAllowListEntries: (input, client = db) => removeStaleAllowListEntries(client, input),
    restoreWorkspaceRepositories: (input, client = db) =>
      restoreWorkspaceRepositories(client, input),
  });
}
