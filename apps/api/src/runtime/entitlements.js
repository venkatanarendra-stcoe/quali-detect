import { createEntitlementRepository, createEntitlementService } from "@qmentisai/db";

/**
 * Entitlement service = { checkEntitlement, assertEntitlement, assertWithinLimit, consumeQuota, releaseQuota }
 * (shared with the workers, see packages/db/src/entitlements).
 * @param {{ infra: any }} deps
 */
export function createEntitlements({ infra }) {
  return createEntitlementService({ repository: createEntitlementRepository({ db: infra.db }) });
}
