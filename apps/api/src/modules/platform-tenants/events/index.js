/** Domain events (declared; published once the transactional outbox exists). The platform audit log records each change meanwhile. */
export const PLATFORM_TENANT_EVENT_TYPES = Object.freeze({
  PROVISIONED: "platform.tenant.provisioned",
  SUSPENDED: "platform.tenant.suspended",
  REACTIVATED: "platform.tenant.reactivated",
  DEACTIVATED: "platform.tenant.deactivated",
});
