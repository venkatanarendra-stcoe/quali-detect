# Screens: organization, workspaces and tenants

Status: **Implemented 2026-11-11** (`apps/tenant-web`, `apps/root-console`, `apps/api`). `docs/TENANT_APP_WIREFRAME_SPEC.md` and `docs/ROOT_CONSOLE_WIREFRAME_SPEC.md` do not exist in this repository, so the screen IDs below were interpreted from `docs/design/TENANT_APPLICATION_DESIGN.md` §3.2, §3b.1, §3b.4, `docs/design/ROOT_CONSOLE_DESIGN.md` §3.2 and `docs/architecture/FRONTEND_ARCHITECTURE.md`. If your IDs mean something else, tell me and I will remap.

| ID | Screen | Route | Route permission | Data |
|---|---|---|---|---|
| T-06 | Organization overview | `/overview` | `dashboard.view` | `GET /workspaces` (counts and cards), `GET /users`, `GET /groups` for tiles the user may see |
| T-07 | Workspaces list | `/workspaces` | `workspace.view` in any workspace | `GET /workspaces` (search, status, sort, page in the URL) |
| T-08 | Create workspace | `/workspaces/new` | `workspace.create` | `POST /workspaces`, then `POST /workspaces/{id}/role-assignments` per grant |
| T-40 | Members & groups | `/workspaces/{id}/members` | `workspace.view` | `GET …/members`, `GET …/role-assignments`, `POST/DELETE …` |
| T-44 | Workspace settings | `/workspaces/{id}/settings` | `workspace.update` | `GET/PATCH /workspaces/{id}`, `POST …/archive`, `POST …/restore` |
| R-04 | Tenants list | `/tenants` | `platform.tenant.view` | `GET /platform/tenants` |
| R-05 | Provision tenant | `/tenants/new` | `platform.tenant.create` | `POST /platform/tenants`, `GET /platform/plans` |
| R-06 | Tenant detail | `/tenants/{id}` | `platform.tenant.view` | `GET /platform/tenants/{id}`, `POST …/suspend|reactivate|deactivate` |

## Deviations from the design documents (what is not built, and why)
- **Workspaces list columns:** Repositories, Pipelines, Open findings and Last activity need modules that do not exist yet. Shown: Name, Business unit, Owner, Members, Status, Created.
- **Create workspace:** the design has four steps; the **Policies** step is not built (no policy API). Steps: Details, Members & access, Review. The identifier field and the "Name available" live check are omitted (ids are assigned by the server; a duplicate name is reported on submit, back on step 1).
- **Members & groups:** the table shows direct roles; a person's access that comes only through a group appears on the Groups tab. Changing a role = revoke and add (the API has no role change). Adding people needs tenant-level `user.view` and `role.view` for the pickers; there is no directory-lookup endpoint (`directory.search`) yet, so a workspace admin without those permissions sees Add access disabled with the reason.
- **Create workspace members step** is shown only to users who can view members/groups and roles; others are told they can add access afterwards.
- **Overview:** security tiles (findings, SLA breaches, approvals) do not exist; a placeholder says so.
- **Tenant detail:** no support-access request or drill-in yet (support-access grants are not implemented).

## API additions
- Workspace DTO gains `memberCount` (active roster entries) and `ownerName`.
- New module `platform-tenants` (all `platform` audience; each route has its own `platform.*` permission):
  `GET /platform/tenants`, `POST /platform/tenants`, `GET /platform/tenants/{id}`, `POST /platform/tenants/{id}/suspend|reactivate|deactivate`, `GET /platform/plans`.
  Platform access to tenants is **metadata and counts only**. Every change is written to the platform audit log in the same transaction (`tenant.created|suspended|reactivated|deactivated`, with the reason and a before/after status).

## Rules (Recommended — default applied unless noted)
- **Provisioning** creates the tenant, an optional subscription (status = the initial status), and the first administrator as an **invited** member with the built-in Admin role at tenant scope. Nobody gets access until the invitee accepts (`POST /me/invitations/{tenantId}/accept`), the same consent rule as user invitations. Initial status: Trial (default) or Active. Slug: 3-40 lowercase letters, digits, hyphens; unique; fixed after creation.
- **Plans** shown in the provisioning form are the published versions returned by the API. Plan names, prices and quotas remain open decisions; nothing is hard-coded.
- **Lifecycle:** suspend (from active/trial), reactivate (from suspended; returns to trial if the tenant has a trial subscription, else active), deactivate (from active/trial/suspended). **Deactivation is reversible by a Platform Super Admin until the retention window expires, then terminal** (AUTHORIZATION Q25, 2026-11-11; the window is Open/configurable; `restore` action, permission `platform.tenant.restore`, shown only inside the window; after it the page says deactivation is final). Every action needs a reason (5-500 characters, audited). Suspend and deactivate also need the tenant name typed exactly; the **server checks it too**. Suspension takes effect on the next request: tenant users get 403 `TENANT_SUSPENDED` and see the "organization is not active" page.
- **Tenant detail** hides the lifecycle history unless the caller holds `platform.audit_log.view`; lifecycle buttons that are valid for the status but not permitted are shown disabled with the missing permission named.
- **No role names** are checked anywhere in the UI or API for these screens.
