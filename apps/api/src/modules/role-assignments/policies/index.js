import { ForbiddenError, ValidationError } from "../../../errors/app-error.js";

export const roleAssignmentPolicy = Object.freeze({
  assertWorkspaceMutable(workspace) {
    if (workspace?.status === "archived") {
      throw new ForbiddenError("This workspace is archived.", {
        details: { reason: "workspace_archived" },
      });
    }
  },
  /** An expiry must lie in the future. */
  assertFutureExpiry(expiresAt, now) {
    if (expiresAt && expiresAt <= now) {
      throw new ValidationError(
        [{ path: "expiresAt", code: "too_small", message: "The expiry must be in the future." }],
        { source: "body" },
      );
    }
  },
});
