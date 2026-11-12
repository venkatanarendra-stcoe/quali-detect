import { QUEUE_NAMES, createEventEnvelope } from "@qmentisai/contracts";
import { createOutboxRepository, restoreWorkspaceRepositories } from "@qmentisai/db";
import { NonRetryableError, createOutbox } from "@qmentisai/infra";
import { auditSystem } from "./audit.js";
import { createRepositoryStates } from "./state.js";

/**
 * The single consumer of normalized SCM events (queue `scm-events`, bound to `scm.github.#`; SPEC §9). It applies the
 * events that change repository or installation STATE. Trigger matching and executions belong to the Pipelines module,
 * which will bind its own queue to the same exchange; push and pull-request events are therefore only acknowledged here.
 * Ownership of every referenced repository or link was re-validated against the database before this runs.
 * @param {{ db: any, config: any, logger: any }} deps
 */
export function createScmEventHandler({ db, config, logger }) {
  const outbox = createOutbox({ repository: createOutboxRepository({ db }) });
  const states = createRepositoryStates({
    db,
    outbox,
    maxFailures: config.scm.syncFailuresBeforeDisconnect,
    logger,
  });

  /**
   * Restore on gaining access (SPEC §18.7): repositories were added to a linked installation. For EVERY linked workspace
   * link of that tenant link, the shared restore rule runs for the added repositories only. Each restored repository is
   * audited with the system actor and announced like a connect. Returns the number restored.
   */
  async function restoreAdded({ tenantId, linkId, repositoriesAdded }) {
    const link = await db.scmInstallationLink.findFirst({
      where: {
        id: linkId,
        tenantId,
        status: "linked",
        installation: { status: { not: "revoked" } },
      },
      select: { id: true },
    });
    if (!link) return 0;
    const workspaceLinks = await db.scmWorkspaceLink.findMany({
      where: { tenantId, linkId: link.id, status: "linked", workspace: { status: "active" } },
      select: { id: true, workspaceId: true, linkedByUserId: true },
    });
    let total = 0;
    for (const wl of workspaceLinks)
      total += await db.$transaction(async (tx) => {
        const restored = await restoreWorkspaceRepositories(tx, {
          tenantId,
          workspaceId: wl.workspaceId,
          workspaceLinkId: wl.id,
          tenantLinkId: link.id,
          userId: wl.linkedByUserId,
          accessibleExternalIds: repositoriesAdded,
        });
        for (const row of restored) {
          await auditSystem(tx, {
            tenantId,
            action: "repository.restored",
            targetType: "repository",
            targetId: row.id,
            workspaceId: row.workspaceId,
            metadata: {
              fullName: row.fullName,
              previousReason: row.disconnectReason,
              workspaceLinkId: wl.id,
            },
          });
          await outbox.enqueue(tx, {
            queue: QUEUE_NAMES.NOTIFICATION,
            message: createEventEnvelope({
              type: "repository.connected",
              schemaVersion: 1,
              tenantId,
              workspaceId: row.workspaceId,
              initiator: { type: "system", id: "scm-sync" },
              subject: { type: "repository", id: row.id },
              payload: {
                repositoryId: row.id,
                workspaceId: row.workspaceId,
                provider: "github",
                externalRepoId: row.externalRepoId,
                fullName: row.fullName,
                defaultBranch: row.defaultBranch,
                linkId: link.id,
              },
            }),
          });
        }
        return restored.length;
      });
    return total;
  }

  return async (message, { log }) => {
    const { tenantId, payload } = message;
    switch (message.type) {
      case "scm.push.received":
      case "scm.pull_request.received":
        return log.debug(
          { type: message.type, repositoryId: payload.repositoryId },
          "SCM event acknowledged (the Pipelines module consumes it)",
        );
      case "scm.repository.changed": {
        const data = {
          ...(payload.fullName
            ? {
                fullName: payload.fullName,
                name: payload.fullName.split("/").pop(),
                ownerLogin: payload.fullName.split("/")[0],
              }
            : {}),
          ...(payload.htmlUrl ? { htmlUrl: payload.htmlUrl } : {}),
          ...(payload.archived === null ? {} : { archived: payload.archived }),
          ...(payload.visibility ? { visibility: payload.visibility } : {}),
          ...(payload.defaultBranch ? { defaultBranch: payload.defaultBranch } : {}),
        };
        if (Object.keys(data).length > 0)
          await db.repository.updateMany({ where: { id: payload.repositoryId, tenantId }, data });
        return log.info(
          { repositoryId: payload.repositoryId, action: payload.action },
          "Repository changed on GitHub",
        );
      }
      case "scm.installation.changed": {
        const link = await db.scmInstallationLink.findFirst({
          where: { id: payload.linkId, tenantId },
        });
        if (!link) return log.warn("Installation link not found for the event");
        if (payload.action === "deleted") await states.revokeInstallation(link.installationId);
        else if (payload.action === "suspend")
          await states.suspendInstallation(link.installationId, true);
        else if (payload.action === "unsuspend")
          await states.suspendInstallation(link.installationId, false);
        return log.info({ action: payload.action }, "Installation changed on GitHub");
      }
      case "scm.installation_repositories.changed": {
        if (payload.action === "removed" && payload.repositoriesRemoved.length > 0) {
          const repos = await db.repository.findMany({
            where: {
              tenantId,
              linkId: payload.linkId,
              externalRepoId: { in: payload.repositoriesRemoved },
              status: { not: "disconnected" },
            },
          });
          for (const repo of repos) await states.recordFailure(repo, "access_removed");
        }
        let restored = 0;
        if (payload.action === "added" && payload.repositoriesAdded.length > 0)
          restored = await restoreAdded({ tenantId, ...payload });
        return log.info(
          {
            restored,
            action: payload.action,
            removed: payload.repositoriesRemoved.length,
            added: payload.repositoriesAdded.length,
          },
          "Installation repositories changed on GitHub",
        );
      }
      default:
        throw new NonRetryableError(`The SCM event consumer does not handle "${message.type}".`, {
          reason: "unsupported-message-type",
        });
    }
  };
}
