/**
 * Platform (Root Console) permission catalog: `platform.*` keys only. Kept in its own module so the Root Console can import
 * it without pulling in a single tenant or workspace key (docs/AUTHORIZATION.md §5.5). `permissions.js` composes the full
 * catalog from this list.
 * @typedef {{ key: string, scope: "platform", description: string }} PlatformPermissionDefinition
 */

/** @type {ReadonlyArray<Readonly<PlatformPermissionDefinition>>} */
export const PLATFORM_PERMISSION_CATALOG = Object.freeze(
  [
    ["platform.tenant.view", "List and open tenants (metadata only)"],
    ["platform.tenant.create", "Provision tenants"],
    ["platform.tenant.update", "Edit tenants"],
    ["platform.tenant.suspend", "Suspend a tenant"],
    ["platform.tenant.reactivate", "Reactivate a tenant"],
    ["platform.tenant.deactivate", "Deactivate a tenant"],
    ["platform.plan.view", "See plans and versions"],
    ["platform.plan.manage", "Manage plans and versions"],
    ["platform.subscription.view", "See tenant subscriptions"],
    ["platform.subscription.manage", "Manage tenant subscriptions"],
    ["platform.license.view", "See license grants"],
    ["platform.license.manage", "Manage license grants"],
    ["platform.entitlement.view", "See entitlements"],
    ["platform.entitlement.manage", "Manage entitlements"],
    ["platform.quota.view", "See quotas"],
    ["platform.quota.manage", "Manage quotas"],
    ["platform.usage.view", "See usage and quotas"],
    ["platform.user.view", "See platform users"],
    ["platform.user.manage", "Manage platform users and their roles"],
    ["platform.integration_catalog.view", "See the global integration catalog"],
    ["platform.integration_catalog.manage", "Manage the global integration catalog"],
    ["platform.config.view", "See global configuration and feature flags"],
    ["platform.config.manage", "Manage global configuration and feature flags"],
    ["platform.monitoring.view", "See jobs, queues and errors"],
    ["platform.audit_log.view", "See the platform audit log"],
    ["platform.support.request_access", "Request a scoped, time-limited tenant diagnostics grant"],
    ["platform.support.use_access", "Use an active grant to view diagnostics in one tenant"],
    ["platform.support.approve_access", "Approve a support-access request"],
  ].map(([key, description]) => Object.freeze({ key, scope: "platform", description })),
);

/** Platform permission keys. */
export const PLATFORM_PERMISSION_KEYS = Object.freeze(
  PLATFORM_PERMISSION_CATALOG.map((p) => p.key),
);

const BY_KEY = new Map(PLATFORM_PERMISSION_CATALOG.map((p) => [p.key, p]));

/** Whether `key` is a known platform permission. @param {string} key */
export const isPlatformPermissionKey = (key) => BY_KEY.has(key);
