import { can, canInAnyWorkspace } from "./authorization.js";

/**
 * Navigation DEFINITIONS (defined once here, evaluated by the central authorization engine). Apps add only labels,
 * routes and icons; no code checks role names. An item is shown only when ALL of these hold:
 * `implemented` (its module exists), permitted (`permission` at `scope`), and its route exists in the app.
 *
 * `scope` of an item:
 * - "tenant":       `permission` is a tenant-scope key, checked at tenant scope;
 * - "workspace":    a workspace-scope key, checked in the active workspace (workspace layout);
 * - "anyWorkspace": a workspace-scope key, held in at least one visible workspace (organization layout).
 *
 * Permission keys follow the current catalog (docs/AUTHORIZATION.md). docs/architecture/FRONTEND_ARCHITECTURE.md still
 * names retired prototype keys (`tenant_user.view`); they are mapped here to `user.view` and `role.view`.
 *
 * @typedef {{ id: string, permission: string, scope: "tenant" | "workspace" | "anyWorkspace", implemented: boolean }} NavItemDefinition
 * @typedef {{ id: string, items: readonly NavItemDefinition[] }} NavGroupDefinition
 */

const item = (id, permission, scope, implemented) =>
  Object.freeze({ id, permission, scope, implemented });
const group = (id, items) => Object.freeze({ id, items: Object.freeze(items) });

/** Organization layout (outside a workspace). @type {readonly NavGroupDefinition[]} */
export const ORG_NAV_GROUPS = Object.freeze([
  group("main", [
    item("overview", "dashboard.view", "tenant", true),
    item("workspaces", "workspace.view", "anyWorkspace", true),
  ]),
  group("administration", [
    item("users", "user.view", "tenant", true),
    item("integrations", "integration.view", "tenant", true),
    item("roles", "role.view", "tenant", true),
    item("settings", "tenant_settings.view", "tenant", true),
    item("audit-logs", "audit_log.view_all", "tenant", true),
  ]),
]);

/** Workspace layout (inside /workspaces/:workspaceId/...). @type {readonly NavGroupDefinition[]} */
export const WORKSPACE_NAV_GROUPS = Object.freeze([
  group("workspace", [
    item("dashboard", "workspace.view", "workspace", true),
    item("repositories", "repository.view", "workspace", true),
    item("pipelines", "pipeline.view", "workspace", true),
    item("executions", "execution.view", "workspace", false),
  ]),
  group("security", [
    item("findings", "finding.view", "workspace", false),
    item("security-reviews", "security_review.view", "workspace", false),
    item("approvals", "approval.view", "workspace", false),
    item("remediation", "remediation.view", "workspace", false),
    item("policies", "policy.view", "workspace", true),
    item("reports", "report.view", "workspace", false),
  ]),
  group("workspace-administration", [
    item("members", "workspace.view", "workspace", true),
    item("workspace-roles", "workspace.view_roles", "workspace", true),
    item("activity", "workspace.view_activity", "workspace", true),
    item("workspace-settings", "workspace.update", "workspace", true),
    item("workspace-integrations", "integration.view", "tenant", true),
  ]),
]);

/**
 * Whether one navigation item is permitted (ignores `implemented` and route availability).
 * @param {NavItemDefinition} navItem
 * @param {{ permissions: object, workspaceId?: string | null }} context
 */
export function isNavItemPermitted(navItem, { permissions, workspaceId = null }) {
  switch (navItem.scope) {
    case "tenant":
      return can(permissions, navItem.permission);
    case "anyWorkspace":
      return canInAnyWorkspace(permissions, navItem.permission);
    case "workspace":
      return workspaceId
        ? can(permissions, navItem.permission, { type: "workspace", workspaceId })
        : false;
    default:
      return false;
  }
}

/**
 * Evaluates navigation groups: keeps an item only if `implemented && permitted && isRouteAvailable(id)`, then drops
 * groups left empty. Pure; the same function runs for every role.
 * @param {readonly NavGroupDefinition[]} groups
 * @param {{ permissions: object, workspaceId?: string | null, isRouteAvailable?: (itemId: string) => boolean }} context
 * @returns {Array<{ id: string, items: NavItemDefinition[] }>}
 */
export function evaluateNavigation(
  groups,
  { permissions, workspaceId = null, isRouteAvailable = () => true },
) {
  return groups
    .map((g) => ({
      id: g.id,
      items: g.items.filter(
        (i) =>
          i.implemented &&
          isRouteAvailable(i.id) &&
          isNavItemPermitted(i, { permissions, workspaceId }),
      ),
    }))
    .filter((g) => g.items.length > 0);
}

/**
 * Whether the user may open `itemId` of the workspace layout inside `workspaceId` (used when switching workspaces).
 * @param {string} itemId
 * @param {{ permissions: object, workspaceId: string, isRouteAvailable?: (itemId: string) => boolean }} context
 */
export function canOpenWorkspaceItem(itemId, context) {
  return evaluateNavigation(WORKSPACE_NAV_GROUPS, context).some((g) =>
    g.items.some((i) => i.id === itemId),
  );
}

/** Flat list of every item id of a navigation definition. @param {readonly NavGroupDefinition[]} groups */
export const navItemIds = (groups) => groups.flatMap((g) => g.items.map((i) => i.id));
