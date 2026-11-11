import {
  Boxes,
  Cable,
  ClipboardCheck,
  FileSearch,
  FileText,
  GitBranch,
  History,
  Key,
  LayoutGrid,
  Play,
  Scale,
  ScrollText,
  Settings,
  ShieldAlert,
  Users,
  Workflow,
  Wrench,
} from "lucide-react";
import { canOpenWorkspaceItem } from "@qmentisai/shared";
import { SECTION_ITEM, isRouteAvailable } from "@/app/routes.jsx";
import { parseNavContext } from "@/hooks/use-nav-context.js";

/**
 * App-side presentation of the navigation defined in `@qmentisai/shared`: only labels, icons and URLs live here
 * (icons: DESIGN_SYSTEM.md §11). Which items exist and who sees them is decided by `evaluateNavigation`; nothing here
 * checks permissions or role names.
 */
export const GROUP_LABELS = Object.freeze({
  main: "Main",
  administration: "Administration",
  workspace: "Workspace",
  security: "Security",
  "workspace-administration": "Workspace administration",
});

const org = (label, icon, path, extraPaths = []) => ({
  label,
  icon,
  to: () => path,
  matches: () => [path, ...extraPaths],
});
const ws = (label, icon, segment) => ({
  label,
  icon,
  to: (workspaceId) => `/workspaces/${workspaceId}/${segment}`,
  matches: (workspaceId) => [`/workspaces/${workspaceId}/${segment}`],
});

export const NAV_ITEMS = Object.freeze({
  // organization layout
  overview: org("Organization overview", LayoutGrid, "/overview"),
  workspaces: org("Workspaces", Boxes, "/workspaces", ["/workspaces/new"]),
  users: org("Users & groups", Users, "/users", ["/groups"]),
  integrations: org("Integrations", Cable, "/integrations"),
  roles: org("Roles & permissions", Key, "/roles"),
  settings: org("Organization settings", Settings, "/settings"),
  "audit-logs": org("Audit logs", ScrollText, "/audit-logs"),
  // workspace layout
  dashboard: ws("Dashboard", LayoutGrid, "dashboard"),
  repositories: ws("Repositories", GitBranch, "repositories"),
  pipelines: ws("Pipelines", Workflow, "pipelines"),
  executions: ws("Executions", Play, "executions"),
  findings: ws("Findings", ShieldAlert, "findings"),
  "security-reviews": ws("Security reviews", FileSearch, "security-reviews"),
  approvals: ws("Approvals", ClipboardCheck, "approvals"),
  remediation: ws("Remediation", Wrench, "remediation"),
  policies: ws("Policies", Scale, "policies"),
  reports: ws("Reports", FileText, "reports"),
  members: ws("Members & groups", Users, "members"),
  "workspace-roles": ws("Roles & permissions", Key, "roles"),
  activity: ws("Activity", History, "activity"),
  "workspace-settings": ws("Settings", Settings, "settings"),
  "workspace-integrations": ws("Integrations", Cable, "integrations"),
});

/**
 * Where switching to `targetWorkspaceId` should land (T-00b): the same section (and query, e.g. filters) when the user may
 * open it in the target workspace, otherwise the target's Dashboard.
 * @param {{ pathname: string, search: string, permissions: object, targetWorkspaceId: string }} input
 */
export function resolveSwitchTarget({ pathname, search, permissions, targetWorkspaceId }) {
  const { section } = parseNavContext(pathname);
  const itemId = section ? SECTION_ITEM[section] : undefined;
  if (
    itemId &&
    canOpenWorkspaceItem(itemId, { permissions, workspaceId: targetWorkspaceId, isRouteAvailable })
  ) {
    return `/workspaces/${targetWorkspaceId}/${section}${search}`;
  }
  return `/workspaces/${targetWorkspaceId}/dashboard`;
}
