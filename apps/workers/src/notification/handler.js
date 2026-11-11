import { NonRetryableError } from "@qmentisai/infra";

/**
 * Notification worker handler. Today it only records what it would notify about (the delivery channels belong to the
 * notification module). It runs after validation, ownership verification and the idempotency claim, so it can trust the
 * message and a redelivery never reaches it twice.
 * @returns {(message: any, context: { log: any, attempt: number }) => Promise<void>}
 */
export function createNotificationHandler() {
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
      default:
        throw new NonRetryableError(`The notification worker does not handle "${message.type}".`, {
          reason: "unsupported-message-type",
        });
    }
  };
}
