# ADR-012: Workspace-level source-control linking

- **Status:** Accepted (2026-11-12, approved by the product owner with the changes in SPEC §18.6)
- **Relates to:** ADR-003 (tenant isolation), ADR-008 (security suite), ADR-009 (credentials), `docs/AUTHORIZATION.md` Q26/Q27, SPEC R-2/R-3

## Context

The first design let only a tenant Admin (`integration.manage`) link a GitHub installation for the whole organization; workspaces then routed repositories from it. Teams want workspace admins to connect GitHub themselves. GitHub permits exactly one App installation per account or organization, so several workspaces of one tenant need to share an installation.

## Decision

1. The **installation record stays tenant-scoped** (one linked tenant per installation; cross-tenant claims answer a generic 409). Inside a tenant, any number of **workspace links** reference it; a second workspace reuses the installation.
2. **Authority to attach an installation to a workspace** = GitHub-side proof of ownership (D5, checked for every person linking, including the second workspace) **and** the workspace-scope permission `workspace_integration.manage`. Tenant Admin is not required but holds the permission everywhere.
3. A **per-workspace repository allow-list** limits what a workspace may connect; a repository is on one workspace's list at a time.
4. The linking `state` binds the workspace; consuming it re-checks the permission from the stored workspace.
5. Uninstalling the App on GitHub affects every linked workspace, is audited per workspace and tenant-wide, and notifies tenant `integration.manage` holders and the `workspace_integration.manage` holders of each affected workspace.
6. The linking state has a 10-minute lifetime; consuming it re-checks the permission and the tenant setting and runs D5 again.

## Consequences

- Positive: self-service for workspace admins; tenant isolation unchanged (every new table is tenant-keyed with composite FKs; the security suite gains workspace-vs-workspace checks).
- Negative / risk: a person who administers a GitHub organization and a workspace can bring that organization's installation into their workspace without a tenant Admin's approval. Mitigated by the allow-list, audit, read-only tenant visibility and Admin notification; a tenant setting "Allow workspace admins to link source control" (default on, tenant `integration.manage`, audited) lets the organization switch workspace linking off (Q28 closed).
- The `scm_installation_link_workspaces` scope table and `scm_workspace_link_settings` routing table are replaced by `scm_workspace_links` and `scm_workspace_link_repositories`; repositories reference the workspace link.
