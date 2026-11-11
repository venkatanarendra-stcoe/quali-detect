import { createEntitlementRepository } from "../entitlements/repository.js";
import { createEntitlementService } from "../entitlements/service.js";

/**
 * Entitlement service = { checkEntitlement, assertEntitlement, assertWithinLimit, consumeQuota, releaseQuota }.
 * @param {{ infra: any }} deps
 */
export function createEntitlements({ infra }) {
  return createEntitlementService({ repository: createEntitlementRepository({ db: infra.db }) });
}
