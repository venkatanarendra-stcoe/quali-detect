import { QUEUE_NAMES, createEventEnvelope } from "@qmentisai/contracts";
import { auditSystem } from "./audit.js";

const LIVE_STATUSES = ["active", "unavailable"];

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

  /**
   * active/unavailable -> disconnected, as a compare-and-set: the WHERE carries tenant + id + the expected live status, so
   * `count === 1` proves THIS call made the transition. The audit entry and the outbox message are written only then, in
   * the caller's transaction; a call that finds the row already disconnected (replay, race, another path) writes nothing.
   * The first transition's reason is the one stored (SPEC §16.3 item 7).
   * @returns {Promise<boolean>} whether this call changed the row
   */
  async function disconnect(tx, repo, reason, metadata = {}) {
    const { count } = await tx.repository.updateMany({
      where: { id: repo.id, tenantId: repo.tenantId, status: { in: LIVE_STATUSES } },
      data: { status: "disconnected", disconnectedAt: new Date(), disconnectReason: reason },
    });
    if (count !== 1) return false;
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
    return true;
  }

  return Object.freeze({
    /**
     * The repository could not be reached or is no longer listed. Every call is one observed failure: the counter is
     * incremented ATOMICALLY (`increment`, which also takes the row lock for the rest of the transaction) and the decision
     * uses the value that update returned, never the caller's possibly stale snapshot. First failure of an `active`
     * repository: compare-and-set `active -> unavailable` and one `repository.unavailable` audit entry; failure number
     * `maxFailures`: compare-and-set to `disconnected` (one audit entry, one `repository.disconnected` message). A
     * repository that is already disconnected, or that does not belong to `repo.tenantId`, is left untouched
     * (`"unchanged"`). When two different causes race, the first transition's cause is the one audited and stored as the
     * disconnect reason; `lastSyncError` always holds the latest cause.
     * @returns {Promise<"unavailable" | "disconnected" | "unchanged">}
     */
    async recordFailure(repo, reason) {
      return db.$transaction(async (tx) => {
        let counted;
        try {
          counted = await tx.repository.update({
            where: { id: repo.id, tenantId: repo.tenantId, status: { in: LIVE_STATUSES } },
            data: { consecutiveSyncFailures: { increment: 1 }, lastSyncError: reason },
            select: { consecutiveSyncFailures: true, status: true },
          });
        } catch (error) {
          if (error?.code === "P2025") return "unchanged"; // disconnected meanwhile, or not this tenant's row
          throw error;
        }
        const failures = counted.consecutiveSyncFailures;
        if (failures >= maxFailures) {
          const done = await disconnect(tx, repo, "repo_inaccessible", { failures, cause: reason });
          return done ? "disconnected" : "unchanged";
        }
        const { count } = await tx.repository.updateMany({
          where: { id: repo.id, tenantId: repo.tenantId, status: "active" },
          data: { status: "unavailable" },
        });
        if (count === 1)
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

    /**
     * A successful sync: refresh metadata, reset the counter, and return `unavailable -> active` by compare-and-set (one
     * "recovered" audit entry only for the call that made the transition). A disconnected repository is never revived by a
     * sync (the metadata update requires a live status), and an identity change (`matchedBy: node_id`) is audited once
     * because the update requires the external id the caller saw.
     */
    async recordSuccess(repo, remote, { matchedBy }) {
      return db.$transaction(async (tx) => {
        const scope = { id: repo.id, tenantId: repo.tenantId };
        const recovered = await tx.repository.updateMany({
          where: { ...scope, status: "unavailable" },
          data: { status: "active" },
        });
        const refreshed = await tx.repository.updateMany({
          where: { ...scope, status: { in: LIVE_STATUSES } },
          data: {
            nodeId: remote.nodeId ?? repo.nodeId,
            fullName: remote.fullName,
            name: remote.name,
            ownerLogin: remote.ownerLogin,
            htmlUrl: remote.htmlUrl,
            visibility: remote.visibility,
            defaultBranch: remote.defaultBranch,
            description: repo.description ?? remote.description,
            archived: remote.archived,
            consecutiveSyncFailures: 0,
            lastSyncError: null,
            lastSyncedAt: new Date(),
          },
        });
        if (refreshed.count !== 1) return;
        if (matchedBy === "node_id") {
          const moved = await tx.repository.updateMany({
            where: { ...scope, externalRepoId: repo.externalRepoId },
            data: { externalRepoId: remote.externalRepoId },
          });
          if (moved.count === 1)
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
        }
        if (recovered.count === 1)
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
            let done = 0;
            for (const repo of repos)
              if (await disconnect(tx, repo, "installation_revoked")) done += 1;
            total += done;
            summary.push({ workspaceLink: wl, repositoryCount: done });
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
   * Shared shape of an installation status change, idempotent. In ONE transaction the installation row is changed by a
   * compare-and-set (its WHERE carries the status it must still differ from; `revoked` is terminal for every other status),
   * so `count === 1` proves this call made the change. Per tenant link the audit entries and the notification event are
   * written only for a real change: the installation status changed, or `apply` really changed repositories (each of those
   * is itself a compare-and-set). A repeated or concurrent delivery changes nothing and writes nothing.
   */
  async function changeInstallation(installationId, status, reason, apply) {
    await db.$transaction(async (tx) => {
      const cas = await tx.scmInstallation.updateMany({
        where: {
          id: installationId,
          status: { notIn: status === "revoked" ? ["revoked"] : [status, "revoked"] },
        },
        data: {
          status,
          lastCheckedAt: new Date(),
          // SPEC §16.2: when the installation left `active` and why. A repeat never rewrites the first date or reason.
          statusChangedAt: status === "active" ? null : new Date(),
          statusReason: reason,
        },
      });
      const changed = cas.count === 1;
      if (!changed) {
        const current = await tx.scmInstallation.findUnique({
          where: { id: installationId },
          select: { status: true },
        });
        if (!current) return;
        if (current.status === "revoked" && status !== "revoked") return; // revoked is terminal: later events are ignored
        await tx.scmInstallation.updateMany({
          where: { id: installationId },
          data: { lastCheckedAt: new Date() },
        });
      }
      const links = await tx.scmInstallationLink.findMany({
        where: { installationId, status: "linked" },
        select: { id: true, tenantId: true },
      });
      for (const link of links) {
        const workspaceLinks = await tx.scmWorkspaceLink.findMany({
          where: { tenantId: link.tenantId, linkId: link.id, status: "linked" },
          select: { id: true, workspaceId: true },
        });
        const { total, summary } = await apply(tx, link, workspaceLinks);
        if (!changed && total === 0) continue; // a repeat that changed nothing audits and announces nothing
        await auditSystem(tx, {
          tenantId: link.tenantId,
          action: "scm_installation.status_changed",
          targetType: "scm_installation_link",
          targetId: link.id,
          metadata: { status },
        });
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
        if (status === "revoked" || status === "suspended")
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
