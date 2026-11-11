/**
 * Permission catalog (docs/AUTHORIZATION.md §5.3-5.5). Code-defined and shared by the API, workers, seed and UI.
 * Keys are stable identifiers (`resource.action`, platform keys `platform.resource.action`); each key has exactly one
 * scope: "tenant" (organization-wide), "workspace" (evaluated per workspace) or "platform" (Root Console only).
 * Adding a key requires deciding its default role bundles (roles.js). The catalog is mirrored into the `permissions` table.
 * @typedef {"tenant" | "workspace" | "platform"} PermissionScope
 * @typedef {{ key: string, scope: PermissionScope, description: string }} PermissionDefinition
 */

import { PLATFORM_PERMISSION_CATALOG } from "./platform-permissions.js";

/** @param {PermissionScope} scope @param {Array<[string, string]>} rows */
const define = (scope, rows) => rows.map(([key, description]) => ({ key, scope, description }));

/** @type {ReadonlyArray<Readonly<PermissionDefinition>>} */
export const PERMISSION_CATALOG = Object.freeze(
  [
    ...define("tenant", [
      ["dashboard.view", "Open the tenant overview (data limited to accessible workspaces)"],
      ["workspace.create", "Create workspaces"],
      ["directory.search", "Minimal user and group lookup for pickers"],
      ["user.view", "List tenant users"],
      ["user.manage", "Invite, change and deactivate tenant users"],
      ["group.view", "List groups"],
      ["group.manage", "Create, edit and manage members of groups"],
      ["role.view", "See roles"],
      ["role.manage", "Create, edit and delete custom roles"],
      ["role_assignment.manage_tenant", "Create and revoke tenant-scope role assignments"],
      ["integration.view", "See tenant integrations"],
      ["integration.manage", "Configure tenant integrations"],
      ["tenant_settings.view", "See organization settings"],
      ["tenant_settings.manage", "Change organization settings"],
      ["usage.view", "See usage and consumption"],
      ["audit_log.view_all", "See the tenant-wide audit log"],
    ]),
    ...define("workspace", [
      ["workspace.view", "See the workspace (gate for seeing anything inside it)"],
      ["workspace.update", "Edit workspace details"],
      ["workspace.archive", "Archive or restore a workspace"],
      ["workspace.manage_members", "Add and remove members and groups, assign workspace roles"],
      ["workspace.view_roles", "See the workspace role matrix"],
      ["workspace.view_activity", "See workspace activity"],
      ["policy.view", "See workspace policies"],
      ["policy.manage", "Change workspace policy overrides"],
      ["repository.view", "See repositories"],
      ["repository.connect", "Connect repositories from a provider"],
      ["repository.sync", "Sync a repository, test or rotate its webhook"],
      ["repository.toggle", "Enable or disable a repository"],
      ["repository.update", "Edit repository settings"],
      ["repository.manage_access", "Restrict a repository to groups"],
      ["repository.disconnect", "Disconnect a repository or revoke provider access"],
      ["pipeline.view", "See pipelines"],
      ["pipeline.manage", "Create, change, enable and disable pipelines"],
      ["pipeline.delete", "Delete a pipeline"],
      ["execution.view", "See executions and scan history"],
      ["execution.run", "Start executions"],
      ["execution.cancel", "Cancel executions"],
      ["scan.run_manual", "Start manual DAST and Asset Discovery scans"],
      ["finding.view", "See findings and evidence (secrets stay redacted)"],
      ["finding.comment", "Comment on findings"],
      ["security_review.view", "See the security review queue"],
      ["finding.review", "Record a true or false positive decision"],
      ["approval.view", "See the approval queue"],
      ["approval.approve", "Approve a TP/FP decision"],
      ["approval.reject", "Reject a TP/FP decision"],
      ["remediation.view", "See remediation work"],
      ["finding.assign", "Assign an approved true positive for remediation"],
      ["finding.remediate", "Work on and submit a fix"],
      ["finding.suppress", "Suppress a finding (workflow to be specified)"],
      ["finding.accept_risk", "Accept the risk of a finding (workflow to be specified)"],
      ["report.view", "See reports"],
      ["report.export", "Export reports"],
      ["audit_log.view", "See the workspace audit log"],
    ]),
    ...PLATFORM_PERMISSION_CATALOG,
  ].map((permission) => Object.freeze(permission)),
);

/** Lookup by key. @type {ReadonlyMap<string, Readonly<PermissionDefinition>>} */
const BY_KEY = new Map(PERMISSION_CATALOG.map((permission) => [permission.key, permission]));

/** Map of CONSTANT_NAME -> key, e.g. `PERMISSIONS.WORKSPACE_MANAGE_MEMBERS === "workspace.manage_members"`. */
export const PERMISSIONS = Object.freeze(
  Object.fromEntries(
    PERMISSION_CATALOG.map(({ key }) => [key.toUpperCase().replaceAll(".", "_"), key]),
  ),
);

/** @param {string} key */
export const isPermissionKey = (key) => BY_KEY.has(key);

/** @param {string} key @returns {Readonly<PermissionDefinition> | undefined} */
export const getPermission = (key) => BY_KEY.get(key);

/** All keys of one scope. @param {PermissionScope} scope */
export const permissionKeysByScope = (scope) =>
  PERMISSION_CATALOG.filter((permission) => permission.scope === scope).map(
    (permission) => permission.key,
  );
