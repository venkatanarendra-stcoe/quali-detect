import { WORKSPACE_INCLUDE } from "../lib/workspace-include.js";
import { NotFoundError } from "../errors/app-error.js";

/**
 * Scope resolvers for `authorize(permissionKey, scopeResolver)`. A resolver declares the permission scope it produces
 * (`scopeType`, checked against the key at startup) and `resolve(request, { tenantId, db })`, which loads the target
 * resource WITH the tenant filter and returns `{ scope, resource }`, or `null` when it does not exist in the caller's
 * tenant (the engine answers 404, identical to "not visible").
 */

/** Tenant-level operations: no resource to load. */
export const tenantScope = Object.freeze({
  scopeType: "tenant",
  resolve: async () => ({ scope: { type: "tenant" }, resource: null }),
});

/**
 * Operations inside one workspace, identified by a route param. Loads `workspace` by id AND tenant.
 * @param {string} [param]
 */
export function workspaceScope(param = "workspaceId") {
  return Object.freeze({
    scopeType: "workspace",
    async resolve(request, { tenantId, db }) {
      const id = request.params?.[param];
      if (typeof id !== "string") throw new NotFoundError();
      const workspace = await db.workspace.findFirst({
        where: { tenantId, id },
        include: WORKSPACE_INCLUDE,
      });
      return workspace
        ? { scope: { type: "workspace", workspaceId: workspace.id }, resource: workspace }
        : null;
    },
  });
}
