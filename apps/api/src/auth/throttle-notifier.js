import { createEventEnvelope, QUEUE_NAMES } from "@qmentisai/contracts";
import { AUDIT_ACTIONS } from "../audit/actions.js";
import { IDENTITY_EVENT_TYPES } from "../modules/identity/events/index.js";

/**
 * Reacts when a sign-in or MFA streak reaches the delay cap: records an audit entry for the real account (if there is
 * one) and emits the "account under attack" notification event.
 *
 * It runs in the background (never awaited by the request) and treats missing accounts as a silent no-op, so neither the
 * response nor its timing reveals whether an account exists.
 *
 * Notification: the event `identity.account.throttle_cap_reached` is written to the transactional outbox (one per tenant
 * the account belongs to, or one platform-level event) and delivered to the notification worker, which for now logs it.
 * The delivery channel (e-mail to the account owner) belongs to the notification module (Open, OPEN_DECISIONS.md).
 * @param {{ db: any, audit: { tenant: Function, platform: Function }, logger: import("pino").Logger, outbox: ReturnType<typeof import("@qmentisai/infra").createOutbox> }} deps
 */
export function createThrottleNotifier({ db, audit, logger, outbox }) {
  async function handle({ audience, identifier, ip, scope }) {
    // "platform-mfa" identifies the account by id; the others by e-mail.
    if (audience === "platform-mfa") {
      const user = await db.platformUser.findUnique({
        where: { id: identifier },
        select: { id: true },
      });
      if (!user) return;
      await audit.platform({
        actorPlatformUserId: user.id,
        action: AUDIT_ACTIONS.PLATFORM_AUTH_THROTTLE_CAP_REACHED,
        metadata: { factor: "mfa", scope },
        ipAddress: ip,
      });
      await notify({ audience, accountId: user.id, scope });
    } else if (audience === "platform") {
      const user = await db.platformUser.findUnique({
        where: { email: identifier },
        select: { id: true },
      });
      if (!user) return;
      await audit.platform({
        actorPlatformUserId: user.id,
        action: AUDIT_ACTIONS.PLATFORM_AUTH_THROTTLE_CAP_REACHED,
        metadata: { factor: "password", scope },
        ipAddress: ip,
      });
      await notify({ audience, accountId: user.id, scope });
    } else {
      const user = await db.user.findUnique({
        where: { email: identifier },
        select: {
          id: true,
          memberships: { where: { status: "active" }, select: { tenantId: true }, take: 10 },
        },
      });
      if (!user) return;
      for (const { tenantId } of user.memberships)
        await audit.tenant({
          tenantId,
          actorUserId: user.id,
          action: AUDIT_ACTIONS.AUTH_THROTTLE_CAP_REACHED,
          metadata: { factor: "password", scope },
          ipAddress: ip,
        });
      await notify({
        audience,
        accountId: user.id,
        scope,
        tenantIds: user.memberships.map((m) => m.tenantId),
      });
    }
  }

  /** Writes the alert to the outbox: one event per tenant of a tenant account, one tenant-less event for platform accounts. */
  async function notify({ audience, accountId, scope, tenantIds = [undefined] }) {
    if (audience === "tenant" && tenantIds.length === 0) return; // a tenant account without a tenant: nothing to tell
    const targets = audience === "tenant" ? tenantIds : [undefined];
    for (const tenantId of targets) {
      await db.$transaction((tx) =>
        outbox.enqueue(tx, {
          queue: QUEUE_NAMES.NOTIFICATION,
          message: createEventEnvelope({
            type: IDENTITY_EVENT_TYPES.ACCOUNT_THROTTLE_CAP_REACHED,
            schemaVersion: 1,
            ...(tenantId ? { tenantId } : {}),
            initiator: { type: "system", id: "auth-throttle" },
            subject: { type: "account", id: accountId },
            payload: { audience, accountId, throttleScope: scope },
          }),
        }),
      );
    }
  }

  return (event) => {
    handle(event).catch((error) =>
      logger.error({ err: error }, "Throttle cap notification failed"),
    );
  };
}
