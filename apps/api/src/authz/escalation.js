import { ERROR_CODES } from "@qmentisai/contracts";
import { findUngrantableKeys, partitionPermissionKeys } from "@qmentisai/shared";
import { AppError } from "../errors/app-error.js";

/**
 * Escalation guard (docs/AUTHORIZATION.md §5.6, §6.2, SOD-3): refuses with 403 ROLE_ESCALATION when `actorPermissions`
 * do not cover every key of a role being created, edited or handed out. Key names are logged by callers, not returned
 * (whether 403 bodies may name permissions is Open, Q13); the response carries only the number of missing keys.
 * @param {object} actorPermissions PermissionSet of the actor
 * @param {readonly string[]} keys Permission keys of the role (or of the keys being added)
 * @param {{ scope: "tenant" } | { scope: "workspace", workspaceId: string }} target Where the keys take effect
 * @param {{ self?: boolean }} [options] `self`: the actor is granting to themselves (or to a group they belong to)
 */
export function assertCanGrant(actorPermissions, keys, target, { self = false } = {}) {
  const { tenantKeys, workspaceKeys } = partitionPermissionKeys(keys);
  const missing = findUngrantableKeys(actorPermissions, { tenantKeys, workspaceKeys }, target, {
    self,
  });
  if (missing.length > 0) {
    throw new AppError(
      ERROR_CODES.ROLE_ESCALATION,
      "You cannot grant permissions that you do not hold.",
      {
        details: { missingCount: missing.length, reason: self ? "self_escalation" : "escalation" },
      },
    );
  }
}

/** The escalation target of an assignment. @param {{ scopeType: "tenant" | "workspace", workspaceId?: string | null }} assignment */
export const targetOfAssignment = (assignment) =>
  assignment.scopeType === "tenant"
    ? { scope: "tenant" }
    : { scope: "workspace", workspaceId: assignment.workspaceId };
