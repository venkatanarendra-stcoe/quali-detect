import { PERMISSION_CATALOG } from "./permissions.js";

/**
 * Central authorization engine (docs/AUTHORIZATION.md §5-§6). PURE: no I/O, no clock unless passed, no framework, so the
 * API enforces with it and the frontends use the same `can` on the permissions returned by `GET /api/v1/me`.
 * Decisions are made on permission KEYS only; role names never appear here or in callers.
 */

const SCOPE_BY_KEY = new Map(PERMISSION_CATALOG.map((p) => [p.key, p.scope]));

/** Tenant statuses that may use the application (suspended and deactivated are rejected). */
export const USABLE_TENANT_STATUSES = Object.freeze(["active", "trial"]);

/**
 * @typedef {object} WorkspacePermissions
 * @property {string} id
 * @property {string} name
 * @property {string} status
 * @property {string[]} permissions Sorted workspace-scope keys held in this workspace.
 *
 * @typedef {object} PermissionSet Effective permissions of one user inside one tenant (the shape `GET /me` returns).
 * @property {string[]} tenant Sorted tenant-scope keys.
 * @property {string[]} allWorkspaces Workspace-scope keys held in EVERY workspace (from tenant-scope assignments).
 * @property {WorkspacePermissions[]} workspaces Visible workspaces only (those where `workspace.view` is held).
 * @property {string[]} [platform] Platform keys (platform principals only).
 *
 * @typedef {{ type: "tenant" } | { type: "workspace", workspaceId: string } | { type: "platform" }} PermissionScope
 *
 * @typedef {object} AssignmentInput
 * @property {string} tenantId
 * @property {"user" | "group"} subjectType
 * @property {string} subjectId User id or group id.
 * @property {"tenant" | "workspace"} scopeType
 * @property {string | null} [workspaceId]
 * @property {string} status "active" | "suspended"
 * @property {Date | string | null} [expiresAt]
 * @property {string[]} permissionKeys Keys of the assigned role.
 */

/** @returns {PermissionSet} */
const emptyPermissions = () => ({ tenant: [], allWorkspaces: [], workspaces: [] });

/**
 * Combines direct and group role assignments, tenant and workspace scope, into effective permissions (§6.1).
 * - Preconditions (§5.11): active user, usable tenant, ACTIVE tenant membership; otherwise the result is empty.
 * - Only assignments of this tenant that are active and not expired count (decision 2); group assignments count only for
 *   groups the user is a member of (flat groups, decision 4); group membership alone grants nothing.
 * - Tenant-scope assignment: tenant keys + workspace keys in every workspace. Workspace-scope assignment: workspace keys
 *   of that workspace only. Platform and unknown keys are ignored. Grant-only: the result is a union (decision 3).
 * - A workspace is returned only if `workspace.view` is held there (otherwise it behaves as if it did not exist).
 * @param {{
 *   user: { id: string, status: string, groupIds?: string[] },
 *   tenant: { id: string, status: string },
 *   membership: { status: string } | null | undefined,
 *   assignments: AssignmentInput[],
 *   workspaces: Array<{ id: string, tenantId: string, name: string, status: string }>,
 *   now?: Date,
 * }} context
 * @param {string} [workspaceId] Limit the result to one workspace.
 * @returns {PermissionSet}
 */
export function resolveEffectivePermissions(context, workspaceId) {
  const { user, tenant, membership, assignments, workspaces, now = new Date() } = context;
  if (!user || user.status !== "active") return emptyPermissions();
  if (!tenant || !USABLE_TENANT_STATUSES.includes(tenant.status)) return emptyPermissions();
  if (membership?.status !== "active") return emptyPermissions();

  const groupIds = new Set(user.groupIds ?? []);
  const tenantKeys = new Set();
  const everyWorkspace = new Set();
  const perWorkspace = new Map();
  for (const a of assignments) {
    if (a.tenantId !== tenant.id || a.status !== "active") continue;
    if (a.expiresAt && new Date(a.expiresAt) <= now) continue;
    const applies =
      a.subjectType === "user"
        ? a.subjectId === user.id
        : a.subjectType === "group" && groupIds.has(a.subjectId);
    if (!applies) continue;
    for (const key of a.permissionKeys) {
      const scope = SCOPE_BY_KEY.get(key);
      if (scope === "tenant" && a.scopeType === "tenant") tenantKeys.add(key);
      else if (scope === "workspace") {
        if (a.scopeType === "tenant") everyWorkspace.add(key);
        else if (a.workspaceId) {
          if (!perWorkspace.has(a.workspaceId)) perWorkspace.set(a.workspaceId, new Set());
          perWorkspace.get(a.workspaceId).add(key);
        }
      }
    }
  }
  const visible = [];
  for (const ws of workspaces) {
    if (ws.tenantId !== tenant.id || (workspaceId && ws.id !== workspaceId)) continue;
    const keys = new Set([...everyWorkspace, ...(perWorkspace.get(ws.id) ?? [])]);
    if (keys.has("workspace.view")) {
      visible.push({ id: ws.id, name: ws.name, status: ws.status, permissions: [...keys].sort() });
    }
  }
  return {
    tenant: [...tenantKeys].sort(),
    allWorkspaces: [...everyWorkspace].sort(),
    workspaces: visible.sort((a, b) => a.name.localeCompare(b.name)),
  };
}

/**
 * Whether the permission set grants `permissionKey` in `scope`. The key's catalog scope must match the scope type:
 * asking for a workspace key at tenant scope (or an unknown key) is a programming error and throws, so a bug cannot
 * silently become "allowed" or "denied".
 * @param {Partial<PermissionSet> | null | undefined} permissions
 * @param {string} permissionKey
 * @param {PermissionScope} [scope]
 * @returns {boolean}
 */
export function can(permissions, permissionKey, scope = { type: "tenant" }) {
  const keyScope = SCOPE_BY_KEY.get(permissionKey);
  if (!keyScope) throw new TypeError(`Unknown permission key "${permissionKey}".`);
  if (keyScope !== scope.type) {
    throw new TypeError(
      `"${permissionKey}" is a ${keyScope}-scope permission and cannot be checked at ${scope.type} scope.`,
    );
  }
  if (!permissions) return false;
  if (scope.type === "tenant") return permissions.tenant?.includes(permissionKey) ?? false;
  if (scope.type === "platform") return permissions.platform?.includes(permissionKey) ?? false;
  const workspace = permissions.workspaces?.find((w) => w.id === scope.workspaceId);
  return workspace?.permissions.includes(permissionKey) ?? false;
}

/**
 * Whether a workspace-scope key is held in at least one visible workspace (for navigation and menus, never for enforcement).
 * @param {Partial<PermissionSet> | null | undefined} permissions
 * @param {string} permissionKey
 */
export function canInAnyWorkspace(permissions, permissionKey) {
  if (SCOPE_BY_KEY.get(permissionKey) !== "workspace") {
    throw new TypeError(`"${permissionKey}" is not a workspace-scope permission.`);
  }
  return permissions?.workspaces?.some((w) => w.permissions.includes(permissionKey)) ?? false;
}

/** Ids of the workspaces the caller can see. @param {Partial<PermissionSet> | null | undefined} permissions */
export const visibleWorkspaceIds = (permissions) =>
  (permissions?.workspaces ?? []).map((w) => w.id);

/**
 * Splits permission keys by catalog scope. `platform` and `unknown` keys must be rejected by callers (roles never hold them).
 * @param {readonly string[]} keys
 */
export function partitionPermissionKeys(keys) {
  const result = { tenantKeys: [], workspaceKeys: [], platformKeys: [], unknownKeys: [] };
  for (const key of new Set(keys)) {
    const scope = SCOPE_BY_KEY.get(key);
    if (scope === "tenant") result.tenantKeys.push(key);
    else if (scope === "workspace") result.workspaceKeys.push(key);
    else if (scope === "platform") result.platformKeys.push(key);
    else result.unknownKeys.push(key);
  }
  return result;
}

/**
 * Capability-based "tenant administrator" test (no role names): holds both `role.manage` and `role_assignment.manage_tenant`.
 * Such callers may grant keys they do not hold themselves (decision 5: approval keys absent from Admin can be granted
 * through custom roles), but never to themselves (SOD-3).
 * @param {Partial<PermissionSet> | null | undefined} permissions
 */
export const isTenantAdministrator = (permissions) =>
  can(permissions, "role.manage") && can(permissions, "role_assignment.manage_tenant");

/**
 * Escalation guard (§5.6, §6.2, SOD-3): the keys of a role the actor may NOT hand out.
 * - target `{ scope: "tenant" }`: tenant keys must be held at tenant scope; workspace keys must be held in every workspace.
 * - target `{ scope: "workspace", workspaceId }`: only workspace keys count (tenant keys are ignored at workspace scope)
 *   and must be held in that workspace.
 * - tenant administrators are exempt unless `self` is true (granting to oneself).
 * @param {Partial<PermissionSet>} actor
 * @param {{ tenantKeys?: readonly string[], workspaceKeys?: readonly string[] }} keys
 * @param {{ scope: "tenant" } | { scope: "workspace", workspaceId: string }} target
 * @param {{ self?: boolean }} [options]
 * @returns {string[]} sorted missing keys; empty means allowed
 */
export function findUngrantableKeys(actor, keys, target, { self = false } = {}) {
  if (!self && isTenantAdministrator(actor)) return [];
  const missing = [];
  const { tenantKeys = [], workspaceKeys = [] } = keys;
  if (target.scope === "tenant") {
    for (const key of tenantKeys) if (!can(actor, key)) missing.push(key);
    for (const key of workspaceKeys) if (!actor?.allWorkspaces?.includes(key)) missing.push(key);
  } else {
    for (const key of workspaceKeys) {
      if (!can(actor, key, { type: "workspace", workspaceId: target.workspaceId }))
        missing.push(key);
    }
  }
  return missing.sort();
}
