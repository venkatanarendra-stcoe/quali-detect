/** Audit actions the platform log can contain (filter options). The server validates the value. */
export const PLATFORM_AUDIT_ACTIONS = [
  "platform.auth.login",
  "platform.auth.logout",
  "platform.auth.mfa_verified",
  "platform.auth.mfa_failed",
  "platform.auth.throttle_cap_reached",
  "tenant.created",
  "tenant.updated",
  "tenant.suspended",
  "tenant.reactivated",
  "tenant.deactivated",
  "tenant.restored",
];
