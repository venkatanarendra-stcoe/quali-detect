export const MODULE_NAME = "platform-tenants";
export const API_PREFIX = "/api/v1/platform";
export const OPENAPI_TAG = "Platform tenants";
export const SORTABLE_FIELDS = Object.freeze(["name", "slug", "status", "createdAt"]);
export const TENANT_STATUSES = Object.freeze(["active", "trial", "suspended", "deactivated"]);

/**
 * Tenant lifecycle (docs/design/ROOT_CONSOLE_DESIGN.md §3.2). Suspend and deactivate need the tenant name typed as
 * confirmation; every transition needs a reason and is written to the platform audit log.
 * A deactivated tenant can be restored by a Platform Super Admin (`restore`, its own permission) until its retention window
 * ends (checked when the action is taken; no purge job); after that deactivation is terminal (AUTHORIZATION Q25).
 * `restore` is distinct from `reactivate` (suspended to active).
 */
export const LIFECYCLE = Object.freeze({
  suspend: {
    from: ["active", "trial"],
    permission: "platform.tenant.suspend",
    confirm: true,
    auditAction: "tenant.suspended",
  },
  reactivate: {
    from: ["suspended"],
    permission: "platform.tenant.reactivate",
    confirm: false,
    auditAction: "tenant.reactivated",
  },
  deactivate: {
    from: ["active", "trial", "suspended"],
    permission: "platform.tenant.deactivate",
    confirm: true,
    auditAction: "tenant.deactivated",
  },
  restore: {
    from: ["deactivated"],
    permission: "platform.tenant.restore",
    confirm: false,
    auditAction: "tenant.restored",
    withinRetention: true,
  },
});
export const LIFECYCLE_ACTIONS = Object.freeze(Object.keys(LIFECYCLE));
