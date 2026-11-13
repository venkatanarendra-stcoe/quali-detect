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

    /**
     * The installation is gone (uninstalled or revoked): it and every repository of EVERY workspace link of its tenant links
     * are disconnected (SPEC §18 A6). Per tenant link: one tenant-level audit entry, one entry per affected workspace, a
     * per-repository entry and event, and one `scm.installation.revoked` event for the notification worker. Repeating it
     * for an installation that is already revoked does nothing (no second notification). `reason` is `uninstalled`
     * (the `installation.deleted` event) or `not_found_on_github` (a call found the installation gone).
     */
    async revokeInstallation(installationId, reason = "uninstalled") {
      await changeInstallation(
        installationId,
        "revoked",
        reason,
        async (tx, link, workspaceLinks) => {
          let total = 0;
          const summary = [];
          for (const wl of workspaceLinks) {
            const repos = await tx.repository.findMany({
              where: {
                tenantId: link.tenantId,
                workspaceId: wl.workspaceId,
                workspaceLinkId: wl.id,
                status: { not: "disconnected" },
              },
            });
            for (const repo of repos) await disconnect(tx, repo, "installation_revoked");
            total += repos.length;
            summary.push({ workspaceLink: wl, repositoryCount: repos.length });
          }
          return { total, summary };
        },
      );
    },

    /** Suspension (or lifting it): repositories of all workspace links become `unavailable` (or return to `active`). */
    async suspendInstallation(installationId, suspended) {
      await changeInstallation(
        installationId,
        suspended ? "suspended" : "active",
        suspended ? "suspended" : null,
        async (tx, link, workspaceLinks) => {
          let total = 0;
          const summary = [];
          for (const wl of workspaceLinks) {
            const scope = {
              tenantId: link.tenantId,
              workspaceId: wl.workspaceId,
              workspaceLinkId: wl.id,
            };
            const changed = suspended
              ? await tx.repository.updateMany({
                  where: { ...scope, status: "active" },
                  data: { status: "unavailable", lastSyncError: "installation_suspended" },
                })
              : await tx.repository.updateMany({
                  where: {
                    ...scope,
                    status: "unavailable",
                    lastSyncError: "installation_suspended",
                  },
                  data: { status: "active", lastSyncError: null },
                });
            total += changed.count;
            summary.push({ workspaceLink: wl, repositoryCount: changed.count });
          }
          return { total, summary };
        },
      );
    },
  });

  /**
   * Shared shape of an installation status change. In one transaction: set the installation status (a no-op when it already
   * has it), then per tenant link write the tenant-level audit entry, run `apply` for the link's workspace links, write one
   * audit entry per affected workspace, and for `revoked` / `suspended` queue the notification event.
   */
  async function changeInstallation(installationId, status, reason, apply) {
    const installation = await db.scmInstallation.findUnique({
      where: { id: installationId },
      select: { id: true, status: true },
    });
    if (!installation) return;
    if (installation.status === "revoked" && status !== "revoked") return; // revoked is terminal: later events are ignored
    const changed = installation.status !== status;
    const links = await db.scmInstallationLink.findMany({
      where: { installationId, status: "linked" },
      select: { id: true, tenantId: true },
    });
    await db.$transaction(async (tx) => {
      await tx.scmInstallation.update({
        where: { id: installationId },
        data: {
          status,
          lastCheckedAt: new Date(),
          // SPEC §16.2: when the installation left `active` and why. Repeating the same status keeps the first date.
          ...(changed
            ? {
                statusChangedAt: status === "active" ? null : new Date(),
                statusReason: reason,
              }
            : {}),
        },
      });
      for (const link of links) {
        await auditSystem(tx, {
          tenantId: link.tenantId,
          action: "scm_installation.status_changed",
          targetType: "scm_installation_link",
          targetId: link.id,
          metadata: { status },
        });
        const workspaceLinks = await tx.scmWorkspaceLink.findMany({
          where: { tenantId: link.tenantId, linkId: link.id, status: "linked" },
          select: { id: true, workspaceId: true },
        });
        const { total, summary } = await apply(tx, link, workspaceLinks);
        for (const { workspaceLink, repositoryCount } of summary)
          await auditSystem(tx, {
            tenantId: link.tenantId,
            action: "scm_workspace_link.status_changed",
            targetType: "scm_workspace_link",
            targetId: workspaceLink.id,
            workspaceId: workspaceLink.workspaceId,
            metadata: {
              status,
              installationLinkId: link.id,
              repositoriesAffected: repositoryCount,
            },
          });
        // Repeating a transition that changed nothing must not notify again.
        if ((status === "revoked" || status === "suspended") && (changed || total > 0))
          await outbox.enqueue(tx, {
            queue: QUEUE_NAMES.NOTIFICATION,
            message: createEventEnvelope({
              type: "scm.installation.revoked",
              schemaVersion: 1,
              tenantId: link.tenantId,
              initiator,
              subject: { type: "installation", id: link.id },
              payload: {
                linkId: link.id,
                cause: status === "revoked" ? "deleted" : "suspended",
                repositoriesAffected: total,
                workspaces: summary.map((x) => ({
                  workspaceId: x.workspaceLink.workspaceId,
                  repositoryCount: x.repositoryCount,
                })),
              },
            }),
          });
      }
    });
  }
}
