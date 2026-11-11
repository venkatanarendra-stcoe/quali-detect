/**
 * Domain events of the module (`domain.entity.action`). Declared for the contract; not published yet (the transactional
 * outbox is not implemented). Authentication events are recorded in the audit log instead.
 */
export const IDENTITY_EVENT_TYPES = Object.freeze({
  USER_LOGGED_IN: "identity.user.logged_in",
  USER_LOGGED_OUT: "identity.user.logged_out",
  ACTIVE_TENANT_CHANGED: "identity.session.active_tenant_changed",
});
