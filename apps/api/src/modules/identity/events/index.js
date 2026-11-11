/**
 * Domain events of the module (`domain.entity.action`). Declared for the contract; not published yet (the transactional
 * outbox is not implemented). Authentication events are recorded in the audit log instead.
 */
export const IDENTITY_EVENT_TYPES = Object.freeze({
  USER_LOGGED_IN: "identity.user.logged_in",
  USER_LOGGED_OUT: "identity.user.logged_out",
  ACTIVE_TENANT_CHANGED: "identity.session.active_tenant_changed",
  /** A sign-in/MFA failure streak reached the throttle cap; the account owner should be notified (outbox pending). */
  ACCOUNT_THROTTLE_CAP_REACHED: "identity.account.throttle_cap_reached",
});
