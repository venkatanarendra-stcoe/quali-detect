/**
 * Stable machine-readable error codes. `RESOURCE_NOT_FOUND` is named in docs/technical/API_STANDARDS.md; the others are the
 * Recommended minimum for the API foundation (Phase 2) and should be confirmed with the identity and module specifications.
 * Add codes here (never inline strings in handlers).
 * @type {Readonly<Record<string, string>>}
 */
export const ERROR_CODES = Object.freeze({
  BAD_REQUEST: "BAD_REQUEST",
  VALIDATION_FAILED: "VALIDATION_FAILED",
  // A pagination cursor that is malformed, tampered with or minted for another endpoint, tenant, sort or filter set.
  INVALID_CURSOR: "INVALID_CURSOR",
  UNAUTHENTICATED: "UNAUTHENTICATED",
  FORBIDDEN: "FORBIDDEN",
  RESOURCE_NOT_FOUND: "RESOURCE_NOT_FOUND",
  CONFLICT: "CONFLICT",
  PAYLOAD_TOO_LARGE: "PAYLOAD_TOO_LARGE",
  UNSUPPORTED_MEDIA_TYPE: "UNSUPPORTED_MEDIA_TYPE",
  INTERNAL_ERROR: "INTERNAL_ERROR",
  SERVICE_UNAVAILABLE: "SERVICE_UNAVAILABLE",
  RATE_LIMITED: "RATE_LIMITED",
  // Tenant context (docs/AUTHORIZATION.md §5.9): the session's active tenant is suspended/deactivated, or the session has none.
  TENANT_SUSPENDED: "TENANT_SUSPENDED",
  TENANT_CONTEXT_REQUIRED: "TENANT_CONTEXT_REQUIRED",
  // A deactivated tenant can no longer be restored: its retention window ended (AUTHORIZATION Q25).
  TENANT_DEACTIVATION_EXPIRED: "TENANT_DEACTIVATION_EXPIRED",
  // Idempotency-Key reused with a different request, or while the first request is still running.
  IDEMPOTENCY_CONFLICT: "IDEMPOTENCY_CONFLICT",
  // An upstream provider (GitHub) is unreachable or rate limited; retry later.
  PROVIDER_UNAVAILABLE: "PROVIDER_UNAVAILABLE",
  // Access management (docs/AUTHORIZATION.md §8, Recommended): stable codes for refused policy outcomes.
  LAST_TENANT_ADMIN: "LAST_TENANT_ADMIN",
  ROLE_IN_USE: "ROLE_IN_USE",
  ROLE_ESCALATION: "ROLE_ESCALATION",
  // Subscription gates (separate from authorization; they never grant permissions).
  ENTITLEMENT_REQUIRED: "ENTITLEMENT_REQUIRED",
  QUOTA_EXCEEDED: "QUOTA_EXCEEDED",
  // Findings (docs/modules/findings/SPEC.md 8): a stale `expectedRev`, a refused state-machine transition, a pending exception, a
  // deleted pipeline or an already decided request. `details.reason` is one of FINDING_CONFLICT_REASONS (@qmentisai/shared).
  FINDING_STATE_CONFLICT: "FINDING_STATE_CONFLICT",
});
