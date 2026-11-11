import { ForbiddenError } from "../../../errors/app-error.js";

export const workspaceMemberPolicy = Object.freeze({
  /** Archived workspaces are read-only. */
  assertWorkspaceMutable(workspace) {
    if (workspace.status === "archived") {
      throw new ForbiddenError("This workspace is archived.", {
        details: { reason: "workspace_archived" },
      });
    }
  },
});
