import { AuditLogsPage } from "@/features/audit/index.js";
import { OverviewPage } from "@/features/organization/pages/overview-page.jsx";
import { PlannedModulePage } from "@/features/placeholders/pages/planned-module-page.jsx";
import {
  CreateWorkspacePage,
  WorkspaceDashboardPage,
  WorkspaceMembersPage,
  WorkspaceSettingsPage,
  WorkspacesPage,
} from "@/features/workspaces/index.js";

const planned = (title, description) => (
  <PlannedModulePage title={title} description={description} />
);

/**
 * Route table = the single list of pages that exist. Navigation consults `isRouteAvailable(itemId)`, so a nav item can
 * only appear when its route is registered here (and its module is `implemented` and the user is permitted).
 * `scope`: "tenant" | "anyWorkspace" for organization routes; workspace routes are checked in the URL's workspace.
 */
export const ORG_ROUTES = [
  {
    itemId: "overview",
    path: "overview",
    permission: "dashboard.view",
    scope: "tenant",
    element: <OverviewPage />,
  },
  {
    itemId: "workspaces",
    path: "workspaces",
    permission: "workspace.view",
    scope: "anyWorkspace",
    element: <WorkspacesPage />,
  },
  {
    path: "workspaces/new",
    permission: "workspace.create",
    scope: "tenant",
    element: <CreateWorkspacePage />,
  },
  {
    itemId: "users",
    path: "users",
    permission: "user.view",
    scope: "tenant",
    element: planned("Users & groups", "User and group administration is planned."),
  },
  {
    path: "groups",
    permission: "group.view",
    scope: "tenant",
    element: planned("Users & groups", "User and group administration is planned."),
  },
  {
    itemId: "integrations",
    path: "integrations",
    permission: "integration.view",
    scope: "tenant",
    element: planned("Integrations", "Source-control and tool integrations are planned."),
  },
  {
    itemId: "roles",
    path: "roles",
    permission: "role.view",
    scope: "tenant",
    element: planned("Roles & permissions", "Role administration is planned."),
  },
  {
    itemId: "settings",
    path: "settings",
    permission: "tenant_settings.view",
    scope: "tenant",
    element: planned("Organization settings", "Organization settings are planned."),
  },
  {
    itemId: "audit-logs",
    path: "audit-logs",
    permission: "audit_log.view_all",
    scope: "tenant",
    element: <AuditLogsPage />,
  },
];

/** Pages under `/workspaces/:workspaceId/`. */
export const WORKSPACE_ROUTES = [
  {
    itemId: "dashboard",
    path: "dashboard",
    permission: "workspace.view",
    element: <WorkspaceDashboardPage />,
  },
  {
    itemId: "repositories",
    path: "repositories",
    permission: "repository.view",
    element: planned("Repositories", "Repository connection and sync are planned."),
  },
  {
    itemId: "pipelines",
    path: "pipelines",
    permission: "pipeline.view",
    element: planned("Pipelines", "Pipeline configuration is planned."),
  },
  {
    itemId: "policies",
    path: "policies",
    permission: "policy.view",
    element: planned("Policies", "Workspace policies are planned."),
  },
  {
    itemId: "members",
    path: "members",
    permission: "workspace.view",
    element: <WorkspaceMembersPage />,
  },
  {
    itemId: "workspace-roles",
    path: "roles",
    permission: "workspace.view_roles",
    element: planned("Roles & permissions", "Workspace role views are planned."),
  },
  {
    itemId: "activity",
    path: "activity",
    permission: "workspace.view_activity",
    element: planned("Activity", "The workspace activity feed is planned."),
  },
  {
    itemId: "workspace-settings",
    path: "settings",
    permission: "workspace.update",
    element: <WorkspaceSettingsPage />,
  },
];

const AVAILABLE = new Set(
  [...ORG_ROUTES, ...WORKSPACE_ROUTES].map((r) => r.itemId).filter(Boolean),
);

/** Whether a page is registered for the navigation item. @param {string} itemId */
export const isRouteAvailable = (itemId) => AVAILABLE.has(itemId);

/** URL segment of a workspace section -> navigation item id (for keeping the section when switching workspaces). */
export const SECTION_ITEM = Object.freeze(
  Object.fromEntries(WORKSPACE_ROUTES.map((r) => [r.path, r.itemId])),
);
