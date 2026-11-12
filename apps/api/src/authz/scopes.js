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

/**
 * Operations on one repository, identified by a route param. Loads the repository by id AND tenant and yields the scope of
 * the workspace it lives in, so `repository.*` permissions are checked in that workspace. A repository that does not exist
 * for the caller's tenant resolves to null (404), exactly like one in a workspace the caller cannot see.
 * @param {string} [param]
 */
export function repositoryScope(param = "repositoryId") {
  return Object.freeze({
    scopeType: "workspace",
    async resolve(request, { tenantId, db }) {
      const id = request.params?.[param];
      if (typeof id !== "string") throw new NotFoundError();
      const repository = await db.repository.findFirst({ where: { tenantId, id } });
      return repository
        ? {
            scope: { type: "workspace", workspaceId: repository.workspaceId },
            resource: repository,
          }
        : null;
    },
  });
}

/**
 * Operations on one pipeline, identified by a route param. Loads the pipeline by id AND tenant (soft-deleted ones too:
 * their history stays readable; mutating services refuse them) and yields the scope of the workspace it lives in, so
 * `pipeline.*` and `execution.*` permissions are checked in that workspace. A pipeline of another tenant, or that does not
 * exist, resolves to null (404), exactly like one in a workspace the caller cannot see.
 * @param {string} [param]
 */
export function pipelineScope(param = "pipelineId") {
  return Object.freeze({
    scopeType: "workspace",
    async resolve(request, { tenantId, db }) {
      const id = request.params?.[param];
      if (typeof id !== "string") throw new NotFoundError();
      const pipeline = await db.pipeline.findFirst({ where: { tenantId, id } });
      return pipeline
        ? { scope: { type: "workspace", workspaceId: pipeline.workspaceId }, resource: pipeline }
        : null;
    },
  });
}
