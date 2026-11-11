import { QUEUE_NAMES, createEventEnvelope } from "@qmentisai/contracts";
import { auditSystem } from "./audit.js";

/**
 * Repository and installation state transitions, shared by the sync job and the SCM event consumer (SPEC R-6, §6.4).
 * Nothing is ever deleted. A transition that changes visible state is audited in the same transaction, and a disconnect
 * announces itself through the outbox.
 * @param {{ db: any, outbox: any, maxFailures: number, logger: any }} deps
 */
export function createRepositoryStates({ db, outbox, maxFailures, logger }) {
  const initiator = { type: "system", id: "scm-sync" };

  function disconnectedEvent(tx, repo, reason) {
    return outbox.enqueue(tx, {
      queue: QUEUE_NAMES.NOTIFICATION,
      message: createEventEnvelope({
        type: "repository.disconnected",
        schemaVersion: 1,
        tenantId: repo.tenantId,
        workspaceId: repo.workspaceId,
        initiator,
        subject: { type: "repository", id: repo.id },
        payload: {
          repositoryId: repo.id,
          workspaceId: repo.workspaceId,
          provider: repo.provider,
          reason,
        },
      }),
    });
  }

  /** active/unavailable -> disconnected (audited, announced). */
  async function disconnect(tx, repo, reason, metadata = {}) {
    await tx.repository.updateMany({
      where: { id: repo.id, tenantId: repo.tenantId, status: { not: "disconnected" } },
      data: { status: "disconnected", disconnectedAt: new Date(), disconnectReason: reason },
    });
    await auditSystem(tx, {
      tenantId: repo.tenantId,
      action: "repository.disconnected",
      targetType: "repository",
      targetId: repo.id,
      workspaceId: repo.workspaceId,
      metadata: { reason, fullName: repo.fullName, ...metadata },
    });
    await disconnectedEvent(tx, repo, reason);
    logger.warn({ repositoryId: repo.id, reason }, "Repository disconnected");
  }

  return Object.freeze({
    /**
     * The repository could not be reached or is no longer listed. First failure: `unavailable`; after `maxFailures`
     * consecutive failures: `disconnected`. Both transitions are audited.
     */
    async recordFailure(repo, reason) {
      return db.$transaction(async (tx) => {
        const failures = repo.consecutiveSyncFailures + 1;
        if (failures >= maxFailures) {
          await tx.repository.updateMany({
            where: { id: repo.id, tenantId: repo.tenantId },
            data: { consecutiveSyncFailures: failures, lastSyncError: reason },
          });
          await disconnect(tx, repo, "repo_inaccessible", { failures, cause: reason });
          return "disconnected";
        }
        await tx.repository.updateMany({
          where: { id: repo.id, tenantId: repo.tenantId },
          data: { status: "unavailable", consecutiveSyncFailures: failures, lastSyncError: reason },
        });
        if (repo.status !== "unavailable")
          await auditSystem(tx, {
            tenantId: repo.tenantId,
            action: "repository.unavailable",
            targetType: "repository",
            targetId: repo.id,
            workspaceId: repo.workspaceId,
            metadata: { reason, failures, fullName: repo.fullName },
          });
        return "unavailable";
      });
    },

    /** A successful sync: refresh metadata, reset the counter, return to `active`. */
    async recordSuccess(repo, remote, { matchedBy }) {
      return db.$transaction(async (tx) => {
        await tx.repository.updateMany({
          where: { id: repo.id, tenantId: repo.tenantId },
          data: {
            ...(matchedBy === "node_id" ? { externalRepoId: remote.externalRepoId } : {}),
            nodeId: remote.nodeId ?? repo.nodeId,
            fullName: remote.fullName,
            name: remote.name,
            ownerLogin: remote.ownerLogin,
            htmlUrl: remote.htmlUrl,
            visibility: remote.visibility,
            defaultBranch: remote.defaultBranch,
            description: repo.description ?? remote.description,
            archived: remote.archived,
            status: "active",
            consecutiveSyncFailures: 0,
            lastSyncError: null,
            lastSyncedAt: new Date(),
          },
        });
        if (matchedBy === "node_id")
          await auditSystem(tx, {
            tenantId: repo.tenantId,
            action: "repository.updated",
            targetType: "repository",
            targetId: repo.id,
            workspaceId: repo.workspaceId,
            metadata: {
              identityMismatch: true,
              matchedBy,
              previousExternalRepoId: repo.externalRepoId,
              externalRepoId: remote.externalRepoId,
            },
          });
        if (repo.status === "unavailable")
          await auditSystem(tx, {
            tenantId: repo.tenantId,
            action: "repository.updated",
            targetType: "repository",
            targetId: repo.id,
            workspaceId: repo.workspaceId,
            metadata: { recovered: true, fullName: remote.fullName },
          });
      });
    },

    /** The installation is gone (uninstalled or revoked): it and every repository of its links are disconnected. */
    async revokeInstallation(installationId) {
      const links = await db.scmInstallationLink.findMany({
        where: { installationId, status: "linked" },
        select: { id: true, tenantId: true },
      });
      await db.$transaction(async (tx) => {
        await tx.scmInstallation.update({
          where: { id: installationId },
          data: { status: "revoked", lastCheckedAt: new Date() },
        });
        for (const link of links) {
          await auditSystem(tx, {
            tenantId: link.tenantId,
            action: "scm_installation.status_changed",
            targetType: "scm_installation_link",
            targetId: link.id,
            metadata: { status: "revoked" },
          });
          const repos = await tx.repository.findMany({
            where: { tenantId: link.tenantId, linkId: link.id, status: { not: "disconnected" } },
          });
          for (const repo of repos) await disconnect(tx, repo, "installation_revoked");
        }
      });
    },

    async suspendInstallation(installationId, suspended) {
      const links = await db.scmInstallationLink.findMany({
        where: { installationId, status: "linked" },
        select: { id: true, tenantId: true },
      });
      await db.$transaction(async (tx) => {
        await tx.scmInstallation.update({
          where: { id: installationId },
          data: { status: suspended ? "suspended" : "active", lastCheckedAt: new Date() },
        });
        for (const link of links) {
          await auditSystem(tx, {
            tenantId: link.tenantId,
            action: "scm_installation.status_changed",
            targetType: "scm_installation_link",
            targetId: link.id,
            metadata: { status: suspended ? "suspended" : "active" },
          });
          if (suspended)
            await tx.repository.updateMany({
              where: { tenantId: link.tenantId, linkId: link.id, status: "active" },
              data: { status: "unavailable", lastSyncError: "installation_suspended" },
            });
          else
            await tx.repository.updateMany({
              where: {
                tenantId: link.tenantId,
                linkId: link.id,
                status: "unavailable",
                lastSyncError: "installation_suspended",
              },
              data: { status: "active", lastSyncError: null },
            });
        }
      });
    },
  });
}
