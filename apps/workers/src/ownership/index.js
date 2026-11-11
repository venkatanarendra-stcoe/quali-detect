import { NonRetryableError } from "@qmentisai/infra";
import { USABLE_TENANT_STATUSES } from "@qmentisai/shared";

/**
 * Per-type ownership checks: does the resource a message talks about really belong to the message's tenant? Each check
 * loads the resource by id AND tenantId (never by id alone). They run on the worker's own database connection, after the
 * envelope is validated and before the handler, so a forged or misrouted message cannot act on another tenant's data.
 * @type {Record<string, (db: any, message: any) => Promise<boolean>>}
 */
const RESOURCE_CHECKS = {
  // The account an alert is about must exist, and a tenant account must belong to the tenant of the message.
  "identity.account.throttle_cap_reached": async (db, message) => {
    const { audience, accountId } = message.payload;
    if (audience === "tenant")
      return Boolean(
        message.tenantId &&
        (await db.tenantMembership.findFirst({
          where: { tenantId: message.tenantId, userId: accountId, status: "active" },
          select: { id: true },
        })),
      );
    return Boolean(
      !message.tenantId &&
      (await db.platformUser.findUnique({ where: { id: accountId }, select: { id: true } })),
    );
  },
  "organization.workspace.created": async (db, message) =>
    Boolean(
      await db.workspace.findFirst({
        where: { id: message.payload.workspaceId, tenantId: message.tenantId },
        select: { id: true },
      }),
    ),
};

/**
 * Builds the consumer `verify` hook (docs/architecture/WORKER_ARCHITECTURE.md, "Processing rules"):
 * 1. the tenant exists and may still use the application (suspended and deactivated tenants get no work);
 * 2. a `workspaceId` carried in the envelope belongs to that tenant;
 * 3. the type-specific resource check (above) passes.
 * Any mismatch is a `NonRetryableError` (dead-letter queue, reason `tenant-not-usable` / `resource-not-in-tenant`).
 * Database outages surface as the underlying (transient) error, so the message is retried.
 * @param {{ db: any }} deps Prisma client
 */
export function createOwnershipVerifier({ db }) {
  return async function verify(message) {
    // Platform-level messages (no tenant) skip the tenant checks; the catalog already refused tenant-scope messages without one.
    if (!message.tenantId) {
      const check = RESOURCE_CHECKS[message.type];
      if (check && !(await check(db, message)))
        throw new NonRetryableError("The referenced account does not exist.", {
          reason: "resource-not-found",
        });
      return;
    }
    const tenant = await db.tenant.findUnique({
      where: { id: message.tenantId },
      select: { id: true, status: true },
    });
    if (!tenant || !USABLE_TENANT_STATUSES.includes(tenant.status))
      throw new NonRetryableError("The tenant does not exist or is not active.", {
        reason: "tenant-not-usable",
      });
    if (message.workspaceId) {
      const workspace = await db.workspace.findFirst({
        where: { id: message.workspaceId, tenantId: message.tenantId },
        select: { id: true },
      });
      if (!workspace)
        throw new NonRetryableError("The workspace does not belong to the tenant.", {
          reason: "resource-not-in-tenant",
        });
    }
    const check = RESOURCE_CHECKS[message.type];
    if (check && !(await check(db, message)))
      throw new NonRetryableError("The referenced resource does not belong to the tenant.", {
        reason: "resource-not-in-tenant",
      });
  };
}
