/**
 * Authorization scope resolver of the findings WRITE routes whose workspace is named in the BODY (the bulk routes of SPEC 8.2; the
 * item routes reuse `findingScope` of `read-scopes.js`). The workspace is loaded by id AND tenant: a workspace of another tenant, a
 * hidden workspace and a random id answer the same 404 (FS-2). The body was validated before this runs, so `workspaceId` is a uuid.
 * @param {string} [field]
 */
export function workspaceBodyScope(field = "workspaceId") {
  return Object.freeze({
    scopeType: "workspace",
    async resolve(request, { tenantId, db }) {
      const id = request.body?.[field];
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
