import { ForbiddenError } from "../../../errors/app-error.js";

/** Business rules of workspaces that are not permission checks. */
export const workspacePolicy = Object.freeze({
  /** Archived workspaces are read-only; only restore (workspace.archive) is allowed (docs/AUTHORIZATION.md §5.7). */
  assertMutable(workspace) {
    if (workspace.status === "archived") {
      throw new ForbiddenError("This workspace is archived.", {
        details: { reason: "workspace_archived" },
      });
    }
  },
});
