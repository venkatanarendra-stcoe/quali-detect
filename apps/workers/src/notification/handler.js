import { NonRetryableError } from "@qmentisai/infra";
import { createRecipientFinder } from "./recipients.js";

/**
 * Notification worker handler. Today it only records what it would notify about (the delivery channels belong to the
 * notification module). It runs after validation, ownership verification and the idempotency claim, so it can trust the
 * message and a redelivery never reaches it twice.
 * @param {{ db: any }} deps database client (recipient lookups, always tenant-filtered)
 * @returns {(message: any, context: { log: any, attempt: number }) => Promise<void>}
 */
export function createNotificationHandler({ db }) {
  const recipients = createRecipientFinder({ db });
  return async (message, { log, attempt }) => {
    switch (message.type) {
      case "organization.workspace.created":
        log.info(
          {
            attempt,
            workspaceId: message.payload.workspaceId,
            workspaceName: message.payload.name,
            ownerUserId: message.payload.ownerUserId,
          },
          "Notification: workspace created",
        );
        return;
      case "repository.connected":
      case "repository.disconnected":
        log.info(
          {
            attempt,
            repositoryId: message.payload.repositoryId,
            workspaceId: message.payload.workspaceId,
            reason: message.payload.reason,
          },
          `Notification: ${message.type}`,
        );
        return;
      case "scm.installation.revoked": {
        // One notification per person (SPEC §18.6): tenant integration managers and the workspace integration managers of
        // each affected workspace. Ids and counts only; the delivery channel belongs to the notification module.
        const { linkId, cause, workspaces } = message.payload;
        const found = await recipients.forInstallationRevoked({
          tenantId: message.tenantId,
          workspaceIds: workspaces.map((w) => w.workspaceId),
        });
        for (const person of found)
          log.warn(
            {
              attempt,
              linkId,
              cause,
              recipientUserId: person.userId,
              tenantLevel: person.tenantLevel,
              workspaceIds: person.workspaceIds,
              affectedWorkspaceCount: workspaces.length,
            },
            "Notification: GitHub installation uninstalled or suspended",
          );
        log.info(
          { attempt, linkId, cause, recipients: found.length },
          "Notification: installation revoked fan-out done",
        );
        return;
      }
      case "identity.account.throttle_cap_reached":
        // Delivery channel (e-mail) belongs to the notification module; for now the alert is recorded.
        log.warn(
          {
            attempt,
            audience: message.payload.audience,
            accountId: message.payload.accountId,
            throttleScope: message.payload.throttleScope,
          },
          "Notification: account reached the sign-in throttle cap",
        );
        return;
      default:
        throw new NonRetryableError(`The notification worker does not handle "${message.type}".`, {
          reason: "unsupported-message-type",
        });
    }
  };
}
