import { AUDIT_ACTIONS } from "../audit/actions.js";
import { IDENTITY_EVENT_TYPES } from "../modules/identity/events/index.js";

/**
 * Reacts when a sign-in or MFA streak reaches the delay cap: records an audit entry for the real account (if there is
 * one) and emits the "account under attack" notification event.
 *
 * It runs in the background (never awaited by the request) and treats missing accounts as a silent no-op, so neither the
 * response nor its timing reveals whether an account exists.
 *
 * Notification delivery: the transactional outbox is not implemented yet, so the event is written as a structured
 * warning log (`event: identity.account.throttle_cap_reached`) and NOT delivered to the user.
 * TODO(outbox): publish through the outbox once it exists, and have the notification worker e-mail the account owner.
 * Open (OPEN_DECISIONS.md): notification channel and wording.
 * @param {{ db: any, audit: { tenant: Function, platform: Function }, logger: import("pino").Logger }} deps
 */
export function createThrottleNotifier({ db, audit, logger }) {
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
      notify({ audience, accountId: user.id, scope });
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
      notify({ audience, accountId: user.id, scope });
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
      notify({ audience, accountId: user.id, scope });
    }
  }

  function notify({ audience, accountId, scope }) {
    logger.warn(
      { event: IDENTITY_EVENT_TYPES.ACCOUNT_THROTTLE_CAP_REACHED, audience, accountId, scope },
      "Account reached the sign-in throttle cap (notification pending: outbox not implemented)",
    );
  }

  return (event) => {
    handle(event).catch((error) =>
      logger.error({ err: error }, "Throttle cap notification failed"),
    );
  };
}
