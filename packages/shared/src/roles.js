import { permissionKeysByScope } from "./permissions.js";

/**
 * Built-in role bundles (docs/AUTHORIZATION.md §5.3-5.6, all Recommended except where the spec says Confirmed).
 * A role is one list of keys: tenant-scope keys only count for tenant-scope assignments, workspace-scope keys count in
 * every workspace for a tenant-scope assignment and in the one workspace for a workspace-scope assignment.
 * Decision 5: the Admin bundle does not include `approval.approve` / `approval.reject`.
 * @typedef {{ key: string, name: string, description: string, permissions: ReadonlyArray<string> }} RoleDefinition
 */

const READ = [
  "workspace.view",
  "repository.view",
  "pipeline.view",
  "execution.view",
  "finding.view",
  "policy.view",
  "report.view",
];
const WORKSPACE_ADMIN_EXCLUDED = new Set(["approval.approve", "approval.reject"]);

/** @param {string} key @param {string} name @param {string} description @param {string[]} permissions @returns {Readonly<RoleDefinition>} */
const role = (key, name, description, permissions) =>
  Object.freeze({ key, name, description, permissions: Object.freeze([...new Set(permissions)]) });

/**
 * Capabilities, as sets of permission keys, used to pick a built-in role BY WHAT IT CAN DO instead of by its name:
 * a role "administers the tenant" when it holds both tenant keys, and "administers a workspace" when it holds every
 * workspace-scope key except the approval decisions (the Admin bundle). Renaming or re-keying a role cannot silently
 * change who becomes an administrator; changing a bundle can, and then the capability simply selects a different role.
 */
export const TENANT_ADMINISTRATOR_KEYS = Object.freeze([
  "role.manage",
  "role_assignment.manage_tenant",
]);
export const WORKSPACE_ADMINISTRATOR_KEYS = Object.freeze(
  permissionKeysByScope("workspace").filter((key) => !WORKSPACE_ADMIN_EXCLUDED.has(key)),
);

/** @type {ReadonlyArray<Readonly<RoleDefinition>>} */
export const BUILT_IN_ROLES = Object.freeze([
  role(
    "admin",
    "Admin",
    "Administers the tenant or workspace. Does not approve security decisions by default.",
    [...permissionKeysByScope("tenant"), ...permissionKeysByScope("workspace")].filter(
      (key) => !WORKSPACE_ADMIN_EXCLUDED.has(key),
    ),
  ),
  role(
    "manager",
    "Manager",
    "Manages workspaces, repositories and pipelines; takes no security decisions.",
    [
      "dashboard.view",
      "workspace.create",
      "directory.search",
      ...READ,
      "workspace.update",
      "workspace.archive",
      "workspace.manage_members",
      "workspace.view_roles",
      "workspace.view_activity",
      "policy.manage",
      "repository.connect",
      "repository.sync",
      "repository.toggle",
      "repository.update",
      "repository.manage_access",
      "repository.disconnect",
      "workspace_integration.view",
      "workspace_integration.manage",
      "pipeline.manage",
      "pipeline.delete",
      "execution.run",
      "execution.cancel",
      "scan.run_manual",
      "finding.comment",
      "security_review.view",
      "approval.view",
      "remediation.view",
      "report.export",
    ],
  ),
  role(
    "lead",
    "Lead",
    "Approves or rejects true/false positive decisions and operates pipelines.",
    [
      "dashboard.view",
      ...READ,
      "workspace.view_activity",
      "repository.sync",
      "repository.toggle",
      "workspace_integration.view",
      "pipeline.manage",
      "execution.run",
      "execution.cancel",
      "scan.run_manual",
      "finding.comment",
      "security_review.view",
      "approval.view",
      "approval.approve",
      "approval.reject",
      "remediation.view",
      "finding.suppress",
      "finding.accept_risk",
      "report.export",
    ],
  ),
  role(
    "security_analyst",
    "Security Analyst",
    "Reviews findings and records true/false positive decisions.",
    [
      "dashboard.view",
      ...READ,
      "workspace.view_activity",
      "finding.comment",
      "security_review.view",
      "finding.review",
      "remediation.view",
    ],
  ),
  role("dev_lead", "Dev Lead", "Manages repositories and drives remediation.", [
    "dashboard.view",
    ...READ,
    "workspace.view_activity",
    "repository.connect",
    "repository.sync",
    "repository.update",
    "workspace_integration.view",
    "pipeline.manage",
    "execution.run",
    "execution.cancel",
    "scan.run_manual",
    "finding.comment",
    "remediation.view",
    "finding.assign",
    "finding.remediate",
  ]),
  role("developer", "Developer", "Remediates findings assigned to them.", [
    "dashboard.view",
    ...READ,
    "finding.comment",
    "remediation.view",
    "finding.remediate",
  ]),
  role("viewer", "Guest / Viewer", "Read-only access.", ["dashboard.view", ...READ]),
]);

/** Platform roles (Root Console). Only Super Admin and Support exist (docs/AUTHORIZATION.md §5.5). @type {ReadonlyArray<Readonly<RoleDefinition>>} */
export const PLATFORM_ROLES = Object.freeze([
  role(
    "super_admin",
    "Platform Super Admin",
    "Full Root Console administration.",
    permissionKeysByScope("platform"),
  ),
  role(
    "support",
    "Platform Support",
    "Read-oriented support; tenant diagnostics only through approved, time-limited grants.",
    [
      "platform.tenant.view",
      "platform.plan.view",
      "platform.subscription.view",
      "platform.license.view",
      "platform.entitlement.view",
      "platform.quota.view",
      "platform.usage.view",
      "platform.integration_catalog.view",
      "platform.config.view",
      "platform.monitoring.view",
      "platform.support.request_access",
      "platform.support.use_access",
    ],
  ),
]);

/** @param {string} key @returns {Readonly<RoleDefinition> | undefined} */
export const getBuiltInRole = (key) => BUILT_IN_ROLES.find((r) => r.key === key);
