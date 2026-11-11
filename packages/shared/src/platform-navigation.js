import { isPlatformPermissionKey } from "./platform-permissions.js";

/**
 * Root Console navigation DEFINITIONS and their evaluation. Deliberately separate from the tenant navigation: this
 * module imports only the platform permission catalog, uses `platform.*` keys exclusively, and takes the flat key list that
 * `GET /api/v1/platform/me` returns. Nothing here knows about tenants, workspaces, tenant roles or tenant permission
 * sets. The Root Console imports it through `@qmentisai/shared/platform`.
 *
 * An item is shown only when `implemented && permitted && route exists`; empty groups are dropped. The app adds labels,
 * icons and URLs (docs/design/ROOT_CONSOLE_DESIGN.md §2 lists the groups).
 *
 * Permission mapping (Recommended — there is no dedicated key for every screen):
 * Platform dashboard -> `platform.tenant.view` (its content is tenant-centric); Subscription Management ->
 * `platform.subscription.view`; Usage & Quotas -> `platform.usage.view`; Support & Diagnostics ->
 * `platform.support.request_access`.
 *
 * @typedef {{ id: string, permission: string, implemented: boolean }} PlatformNavItemDefinition
 * @typedef {{ id: string, items: readonly PlatformNavItemDefinition[] }} PlatformNavGroupDefinition
 */

const item = (id, permission, implemented) => Object.freeze({ id, permission, implemented });
const group = (id, items) => Object.freeze({ id, items: Object.freeze(items) });

/** @type {readonly PlatformNavGroupDefinition[]} */
export const PLATFORM_NAV_GROUPS = Object.freeze([
  group("platform", [
    item("dashboard", "platform.tenant.view", true),
    item("monitoring", "platform.monitoring.view", true),
  ]),
  group("customers", [
    item("tenants", "platform.tenant.view", true),
    item("subscriptions", "platform.subscription.view", true),
    item("licenses", "platform.license.view", true),
    item("entitlements", "platform.entitlement.view", true),
    item("usage-quotas", "platform.usage.view", true),
  ]),
  group("platform-administration", [
    item("platform-users", "platform.user.view", true),
    item("integration-catalog", "platform.integration_catalog.view", true),
    item("global-config", "platform.config.view", true),
  ]),
  group("operations", [
    item("support", "platform.support.request_access", true),
    item("audit-logs", "platform.audit_log.view", true),
  ]),
]);

// Fail at import time if a definition ever references a non-platform key (tenant models must never leak in).
for (const g of PLATFORM_NAV_GROUPS) {
  for (const i of g.items) {
    if (!isPlatformPermissionKey(i.permission)) {
      throw new Error(
        `Platform navigation item "${i.id}" must use a platform.* permission, got "${i.permission}".`,
      );
    }
  }
}

/**
 * Whether the platform principal holds `permissionKey`. Only `platform.*` keys are accepted (a tenant or unknown key is a
 * programming error and throws).
 * @param {readonly string[] | null | undefined} permissionKeys the `permissions` array of `GET /platform/me`
 * @param {string} permissionKey
 */
export function canPlatform(permissionKeys, permissionKey) {
  if (!isPlatformPermissionKey(permissionKey)) {
    throw new TypeError(`"${permissionKey}" is not a platform permission.`);
  }
  return permissionKeys?.includes(permissionKey) ?? false;
}

/**
 * Evaluates the platform navigation with platform permissions only; same function for every platform role.
 * @param {{ permissions: readonly string[], isRouteAvailable?: (itemId: string) => boolean, groups?: readonly PlatformNavGroupDefinition[] }} context
 * @returns {Array<{ id: string, items: PlatformNavItemDefinition[] }>}
 */
export function evaluatePlatformNavigation({
  permissions,
  isRouteAvailable = () => true,
  groups = PLATFORM_NAV_GROUPS,
}) {
  return groups
    .map((g) => ({
      id: g.id,
      items: g.items.filter(
        (i) => i.implemented && isRouteAvailable(i.id) && canPlatform(permissions, i.permission),
      ),
    }))
    .filter((g) => g.items.length > 0);
}
