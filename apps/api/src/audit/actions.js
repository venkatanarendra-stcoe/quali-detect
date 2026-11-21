/**
 * Audit action names (`resource.verb`). Every state change that affects who can do what, tenant lifecycle and sensitive
 * exports is recorded with one of these. Keep names stable: they are queried and shown to tenant administrators.
 */
export const AUDIT_ACTIONS = Object.freeze({
  // Authentication
  AUTH_LOGIN: "auth.login",
  AUTH_LOGOUT: "auth.logout",
  AUTH_TENANT_SWITCHED: "auth.tenant_switched",
  PLATFORM_AUTH_LOGIN: "platform.auth.login",
  PLATFORM_AUTH_LOGOUT: "platform.auth.logout",
  PLATFORM_AUTH_MFA_VERIFIED: "platform.auth.mfa_verified",
  PLATFORM_AUTH_MFA_FAILED: "platform.auth.mfa_failed",
  // A sign-in or MFA failure streak reached the throttle cap (ADR-010)
  AUTH_THROTTLE_CAP_REACHED: "auth.throttle_cap_reached",
  PLATFORM_AUTH_THROTTLE_CAP_REACHED: "platform.auth.throttle_cap_reached",
  // Permission changes
  ROLE_CREATED: "role.created",
  ROLE_UPDATED: "role.updated",
  ROLE_DELETED: "role.deleted",
  ROLE_ASSIGNMENT_CREATED: "role_assignment.created",
  ROLE_ASSIGNMENT_UPDATED: "role_assignment.updated",
  ROLE_ASSIGNMENT_REVOKED: "role_assignment.revoked",
  // Directory
  USER_INVITED: "user.invited",
  USER_ACTIVATED: "user.activated",
  USER_SUSPENDED: "user.suspended",
  USER_REMOVED: "user.removed",
  INVITATION_ACCEPTED: "user.invitation_accepted",
  GROUP_CREATED: "group.created",
  GROUP_UPDATED: "group.updated",
  GROUP_DELETED: "group.deleted",
  GROUP_MEMBER_ADDED: "group.member_added",
  GROUP_MEMBER_REMOVED: "group.member_removed",
  WORKSPACE_CREATED: "workspace.created",
  WORKSPACE_UPDATED: "workspace.updated",
  WORKSPACE_ARCHIVED: "workspace.archived",
  WORKSPACE_RESTORED: "workspace.restored",
  WORKSPACE_MEMBER_ADDED: "workspace.member_added",
  WORKSPACE_MEMBER_REMOVED: "workspace.member_removed",
  // Tenant lifecycle (platform audit log; written by the Root Console tenant module)
  TENANT_CREATED: "tenant.created",
  TENANT_UPDATED: "tenant.updated",
  TENANT_SUSPENDED: "tenant.suspended",
  TENANT_REACTIVATED: "tenant.reactivated",
  TENANT_DEACTIVATED: "tenant.deactivated",
  TENANT_RESTORED: "tenant.restored",
  // Source control (docs/modules/repositories-github/SPEC.md)
  SCM_INSTALLATION_LINKED: "scm_installation.linked",
  SCM_INSTALLATION_UNLINKED: "scm_installation.unlinked",
  // Workspace-level links (SPEC §18, ADR-012)
  SCM_WORKSPACE_LINK_CREATED: "scm_workspace_link.created",
  SCM_WORKSPACE_LINK_REACTIVATED: "scm_workspace_link.reactivated",
  SCM_WORKSPACE_LINK_UNLINKED: "scm_workspace_link.unlinked",
  SCM_WORKSPACE_LINK_STATUS_CHANGED: "scm_workspace_link.status_changed",
  SCM_WORKSPACE_LINK_ALLOW_LIST_UPDATED: "scm_workspace_link.allow_list_updated",
  SCM_SETTINGS_WORKSPACE_LINKING_UPDATED: "scm_settings.workspace_linking_updated",
  SCM_INSTALLATION_STATUS_CHANGED: "scm_installation.status_changed",
  SCM_INSTALLATION_SELECTION_CHANGED: "scm_installation.selection_changed",
  REPOSITORY_CONNECTED: "repository.connected",
  REPOSITORY_UPDATED: "repository.updated",
  REPOSITORY_ENABLED: "repository.enabled",
  REPOSITORY_DISABLED: "repository.disabled",
  REPOSITORY_UNAVAILABLE: "repository.unavailable",
  REPOSITORY_DISCONNECTED: "repository.disconnected",
  REPOSITORY_RESTORED: "repository.restored",
  // Download of the stored (redacted) SBOM document of a repository (docs/modules/scan-engines/SPEC.md 17.r). Metadata: ids and sizes only.
  REPOSITORY_SBOM_DOWNLOADED: "repository.sbom_downloaded",
  // Pipelines and executions (docs/modules/pipelines-triggers/SPEC.md §7.4). Metadata: ids, version numbers, hashes, diff
  // summaries (paths only) and reason codes; never a secret and never commit text.
  PIPELINE_CREATED: "pipeline.created",
  PIPELINE_UPDATED: "pipeline.updated",
  PIPELINE_CONFIG_PUBLISHED: "pipeline.config_published",
  PIPELINE_ENABLED: "pipeline.enabled",
  PIPELINE_DISABLED: "pipeline.disabled",
  PIPELINE_DELETED: "pipeline.deleted",
  PIPELINE_FORK_POLICY_CHANGED: "pipeline.fork_policy_changed",
  PIPELINE_SCHEDULE_CHANGED: "pipeline.schedule_changed",
  EXECUTION_MANUAL_REQUESTED: "execution.manual_requested",
  EXECUTION_MANUAL_DENIED: "execution.manual_denied",
  EXECUTION_BLOCKED: "execution.blocked",
  EXECUTION_SKIPPED: "execution.skipped",
  EXECUTION_CANCELLED_SUPERSEDED: "execution.cancelled_superseded",
  EXECUTION_CANCELLED_PR_CLOSED: "execution.cancelled_pr_closed",
  // Cancel and retry of an execution (docs/modules/executions/SPEC.md part D, §14.1 EXE-007). Metadata: ids, status, mode and
  // reason codes; never log text, never a secret.
  EXECUTION_CANCEL_REQUESTED: "execution.cancel_requested",
  EXECUTION_CANCEL_DENIED: "execution.cancel_denied",
  EXECUTION_CANCELLED: "execution.cancelled",
  EXECUTION_RETRY_REQUESTED: "execution.retry_requested",
  EXECUTION_RETRY_DENIED: "execution.retry_denied",
  // Tenant data-egress consent for an external LLM provider (docs/modules/scan-decisioning/SPEC.md 7.2a). Metadata: previous and new value only.
  TENANT_LLM_CONSENT_CHANGED: "tenant.llm_consent_changed",
  // Secret storage (ADR-009). Entries never contain a value.
  SECRET_CREATED: "secret.created",
  SECRET_ROTATED: "secret.rotated",
  SECRET_DELETED: "secret.deleted",
  // Sensitive exports (any export of findings, audit data, user lists or evidence)
  EXPORT_REQUESTED: "export.requested",
  EXPORT_DOWNLOADED: "export.downloaded",
});

const ACTION_PATTERN = /^[a-z_]+(\.[a-z_]+)+$/;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
export const isUuid = (value) => typeof value === "string" && UUID.test(value);

/**
 * Before/after key diff for permission sets, the audited shape of role changes.
 * @param {readonly string[]} before
 * @param {readonly string[]} after
 */
export function diffKeys(before, after) {
  const b = new Set(before);
  const a = new Set(after);
  return {
    added: [...a].filter((k) => !b.has(k)).sort(),
    removed: [...b].filter((k) => !a.has(k)).sort(),
  };
}

/** @param {string} action */
export function assertAuditAction(action) {
  if (typeof action !== "string" || !ACTION_PATTERN.test(action))
    throw new TypeError(`Invalid audit action "${action}".`);
}
