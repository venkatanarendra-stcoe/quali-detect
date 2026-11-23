/**
 * Authorization scope resolvers of the findings routes (docs/modules/findings/SPEC.md FS-1, FS-2; the shape is that of
 * `apps/api/src/authz/scopes.js`). A resolver loads the target WITH the session's tenant and yields the workspace scope the central
 * engine checks, or `null` (the engine answers the identical 404, the same as "not visible"). Part B, C and D reuse `findingScope` for
 * their item routes.
 */

/**
 * Collection reads of one workspace, identified by a (validated) query parameter, `workspaceId` by default. The workspace is loaded by
 * id AND tenant: a workspace of another tenant, a hidden workspace and a random id all answer the same 404.
 * @param {string} [param]
 */
export function workspaceQueryScope(param = "workspaceId") {
  return Object.freeze({
    scopeType: "workspace",
    async resolve(request, { tenantId, db }) {
      const id = request.query?.[param];
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
 * Operations on one finding, identified by a route param. The finding is looked up by TENANT and id, then authorized in ITS workspace
 * (never by id alone). Only a minimal reference (`id`, `workspaceId`, `pipelineId`) is exposed as the resource: services re-read what
 * they need by tenant, workspace and id.
 * @param {string} [param]
 */
export function findingScope(param = "id") {
  return Object.freeze({
    scopeType: "workspace",
    async resolve(request, { tenantId, db }) {
      const id = request.params?.[param];
      if (typeof id !== "string") return null;
      const finding = await db.finding.findFirst({
        where: { tenantId, id },
        select: { id: true, workspaceId: true, pipelineId: true },
      });
      return finding
        ? { scope: { type: "workspace", workspaceId: finding.workspaceId }, resource: finding }
        : null;
    },
  });
}
