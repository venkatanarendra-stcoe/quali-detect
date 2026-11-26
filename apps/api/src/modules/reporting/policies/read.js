/**
 * Authorization scope resolvers of the reporting READ routes (docs/modules/reporting-dashboards/SPEC.md 3; the shape is that of
 * `apps/api/src/authz/scopes.js`). A resolver loads the target WITH the session's tenant and yields the scope the central engine checks, or
 * `null` (the engine answers the identical 404, the same as "not visible"). While `REPORTING_ENABLED` is not true every resolver answers `null`,
 * so every reporting route is a 404 for an authenticated tenant caller, exactly like a route that does not exist (the module is OFF).
 */

/** @param {any} config @returns {() => boolean} */
export const reportingEnabled = (config) => () => config?.reporting?.enabled === true;

/**
 * A workspace read: `workspaceId` is a validated REQUIRED query parameter, loaded by id AND tenant. Another tenant's workspace, a hidden one
 * and an unknown id all answer the same 404; a visible workspace without the section's key is 403 (the engine decides).
 * @param {() => boolean} enabled
 */
export function reportingWorkspaceScope(enabled) {
  return Object.freeze({
    scopeType: "workspace",
    async resolve(request, { tenantId, db }) {
      if (!enabled()) return null;
      const id = request.query?.workspaceId;
      if (typeof id !== "string") return null;
      const workspace = await db.workspace.findFirst({
        where: { tenantId, id },
        select: { id: true },
      });
      return workspace
        ? {
            scope: { type: "workspace", workspaceId: workspace.id },
            resource: { id: workspace.id },
          }
        : null;
    },
  });
}

/**
 * The Organization Overview: tenant scope, no resource, no workspace or tenant parameter (the strict query refuses one).
 * @param {() => boolean} enabled
 */
export function reportingTenantScope(enabled) {
  return Object.freeze({
    scopeType: "tenant",
    resolve: async () => (enabled() ? { scope: { type: "tenant" }, resource: null } : null),
  });
}
