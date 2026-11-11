/**
 * Authentication events are audited best effort (a failed audit write is logged, never blocks sign-in/out).
 * Thin adapter over the audit service so the auth core keeps its small `tenant(entry)` / `platform(entry)` surface.
 * @param {{ audit: ReturnType<typeof import("../audit/audit-service.js").createAuditService> }} deps
 */
export function createAuthAudit({ audit }) {
  return Object.freeze({
    tenant: (entry) => audit.tenant.recordSafe(entry),
    platform: (entry) => audit.platform.recordSafe(entry),
  });
}
