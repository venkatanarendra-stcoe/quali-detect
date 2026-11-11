/**
 * Audit action names (`resource.verb`). Every state change that affects who can do what, tenant lifecycle and sensitive
 * exports is recorded with one of these. Keep names stable: they are queried and shown to tenant administrators.
 */
export const AUDIT_ACTIONS = Object.freeze({
  // Authentication
  AUTH_LOGIN: "auth.login",
  AUTH_LOGOUT: "auth.logout",
  AUTH_TENANT_SWITCHED: "auth.tenant_switched",
  PLATFORM_AUTH_LOGIN: "platform.auth.login",
  PLATFORM_AUTH_LOGOUT: "platform.auth.logout",
  PLATFORM_AUTH_MFA_VERIFIED: "platform.auth.mfa_verified",
  PLATFORM_AUTH_MFA_FAILED: "platform.auth.mfa_failed",
  // A sign-in or MFA failure streak reached the throttle cap (ADR-010)
  AUTH_THROTTLE_CAP_REACHED: "auth.throttle_cap_reached",
  PLATFORM_AUTH_THROTTLE_CAP_REACHED: "platform.auth.throttle_cap_reached",
  // Permission changes
  ROLE_CREATED: "role.created",
  ROLE_UPDATED: "role.updated",
  ROLE_DELETED: "role.deleted",
  ROLE_ASSIGNMENT_CREATED: "role_assignment.created",
  ROLE_ASSIGNMENT_UPDATED: "role_assignment.updated",
  ROLE_ASSIGNMENT_REVOKED: "role_assignment.revoked",
  // Directory
  USER_INVITED: "user.invited",
  USER_ACTIVATED: "user.activated",
  USER_SUSPENDED: "user.suspended",
  USER_REMOVED: "user.removed",
  INVITATION_ACCEPTED: "user.invitation_accepted",
  GROUP_CREATED: "group.created",
  GROUP_UPDATED: "group.updated",
  GROUP_DELETED: "group.deleted",
  GROUP_MEMBER_ADDED: "group.member_added",
  GROUP_MEMBER_REMOVED: "group.member_removed",
  WORKSPACE_CREATED: "workspace.created",
  WORKSPACE_UPDATED: "workspace.updated",
  WORKSPACE_ARCHIVED: "workspace.archived",
  WORKSPACE_RESTORED: "workspace.restored",
  WORKSPACE_MEMBER_ADDED: "workspace.member_added",
  WORKSPACE_MEMBER_REMOVED: "workspace.member_removed",
  // Tenant lifecycle (platform audit log; written by the Root Console tenant module)
  TENANT_CREATED: "tenant.created",
  TENANT_UPDATED: "tenant.updated",
  TENANT_SUSPENDED: "tenant.suspended",
  TENANT_REACTIVATED: "tenant.reactivated",
  TENANT_DEACTIVATED: "tenant.deactivated",
  TENANT_RESTORED: "tenant.restored",
  // Sensitive exports (any export of findings, audit data, user lists or evidence)
  EXPORT_REQUESTED: "export.requested",
  EXPORT_DOWNLOADED: "export.downloaded",
});

const ACTION_PATTERN = /^[a-z_]+(\.[a-z_]+)+$/;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
export const isUuid = (value) => typeof value === "string" && UUID.test(value);

/**
 * Before/after key diff for permission sets, the audited shape of role changes.
 * @param {readonly string[]} before
 * @param {readonly string[]} after
 */
export function diffKeys(before, after) {
  const b = new Set(before);
  const a = new Set(after);
  return {
    added: [...a].filter((k) => !b.has(k)).sort(),
    removed: [...b].filter((k) => !a.has(k)).sort(),
  };
}

/** @param {string} action */
export function assertAuditAction(action) {
  if (typeof action !== "string" || !ACTION_PATTERN.test(action))
    throw new TypeError(`Invalid audit action "${action}".`);
}
