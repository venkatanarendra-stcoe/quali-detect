# Screens: organization, workspaces and tenants

Status: **Implemented 2026-11-11** (`apps/tenant-web`, `apps/root-console`, `apps/api`). `docs/TENANT_APP_WIREFRAME_SPEC.md` and `docs/ROOT_CONSOLE_WIREFRAME_SPEC.md` do not exist in this repository, so the screen IDs below were interpreted from `docs/design/TENANT_APPLICATION_DESIGN.md` §3.2, §3b.1, §3b.4, `docs/design/ROOT_CONSOLE_DESIGN.md` §3.2 and `docs/architecture/FRONTEND_ARCHITECTURE.md`. If your IDs mean something else, tell me and I will remap.

| ID | Screen | Route | Route permission | Data |
|---|---|---|---|---|
| T-06 | Organization overview | `/overview` | `dashboard.view` | `GET /workspaces` (counts and cards), `GET /users`, `GET /groups` for tiles the user may see |
| T-07 | Workspaces list | `/workspaces` | `workspace.view` in any workspace | `GET /workspaces` (search, status, sort, page in the URL) |
| T-08 | Create workspace | `/workspaces/new` | `workspace.create` | `POST /workspaces`, then `POST /workspaces/{id}/role-assignments` per grant |
| T-40 | Members & groups | `/workspaces/{id}/members` | `workspace.view` | `GET …/members`, `GET …/role-assignments`, `POST/DELETE …` |
| T-44 | Workspace settings | `/workspaces/{id}/settings` | `workspace.update` | `GET/PATCH /workspaces/{id}`, `POST …/archive`, `POST …/restore` |
| T-19 | Audit logs | `/audit-logs` | `audit_log.view_all` | `GET /audit-logs` (actor, action, from, to, result, sort in the URL; "Load more" with `cursor`/`limit`, no total or page count shown, `INVALID_CURSOR` restarts from the first page with a toast; rendered as the audit-log terminal, see "T-19 as built") |
| R-04 | Tenants list | `/tenants` | `platform.tenant.view` | `GET /platform/tenants` (R-04 uses cursor "Load more": `limit` on the first request, `cursor` from `meta.pagination.nextCursor`; no total or pager is shown; search, status, plan and sort stay in the URL) |
| R-05 | Provision tenant | `/tenants/new` | `platform.tenant.create` | `POST /platform/tenants`, `GET /platform/plans` |
| R-06 | Tenant detail | `/tenants/{id}` | `platform.tenant.view` | `GET /platform/tenants/{id}`, `POST …/suspend|reactivate|deactivate` |
| R-28 | Platform audit logs | `/audit-logs` | `platform.audit_log.view` | `GET /platform/audit-logs` (actor, action, tenantId, from, to, result, sort in the URL; cursor "Load more", no total or pager, no `page` param) |

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

## T-19 and R-28 audit log screens (2026-11-11)

No wireframe specs exist for these screens, so they follow `TENANT_APPLICATION_DESIGN.md` §3.16 ("time, actor, action, resource, outcome, correlation ID; filters") and the Root Console list conventions. Table: Time (sortable, newest first), Actor (name and e-mail), Action (sortable), Resource (type and id), Result, Correlation ID, and a Details disclosure (changes, metadata, IP address). R-28 adds a Tenant column. Filters: action, actor, result, date range (and tenant for R-28). Loading, empty (no entries / no matches), error and unauthorized states exist; export is not built (Planned). **Result is derived**: the audit tables record events, not outcomes, so entries whose action ends in `_failed`, `_denied` or `throttle_cap_reached` read as failures and all others as successes (Open: store an explicit result). The tenant API always uses the session's tenant and rejects any tenant parameter; the platform API never shows a tenant's own audit log.

## R-04 and R-28 "Load more" (2026-11-13)

R-04 Tenants and R-28 Platform audit logs show no total ("N tenants", "N entries") and no page-number pager. The first request carries `limit` (20 and 25) and no cursor; the footer button **Load more** requests the next page with `meta.pagination.nextCursor` and appends the rows (`apps/root-console/src/hooks/use-cursor-list.js`); it disappears when `nextCursor` is `null`. Filters and sort are part of the query key, so changing one starts a new list at the first page. `400 INVALID_CURSOR` restarts from the first page with a Sonner toast. Focus moves to the first new row and a polite status says "More rows loaded". Cursors are scoped to the platform principal by the API. Other Root Console lists are planned modules without data yet.

## T-19 as built: audit-log terminal (2026-11-13)

Owner decision (item 6, option 2): the tenant audit log is the `AuditTerminal` (`@qmentisai/ui`; exception recorded in `DESIGN_SYSTEM.md` "Audit-log terminal exception"). A dark, monospace panel in both app themes with the prompt line `<tenant-slug>@qmentisai:~$ tail -f audit.log` (slug from `GET /me` `tenant.slug` via `useSession`) and a sticky header. Columns: timestamp (local `YYYY-MM-DD HH:mm:ss`, sortable; tooltip with the long date), actor (name and e-mail), action (sortable), target (type and id), result (icon plus `success` or `failure`; the component also supports `denied`, unused because the API result is derived). The correlation ID column is no longer in the list: it is in the detail sheet. Filters (action, actor, result, from, to) and sort stay in the URL; the footer is a `-- more --` button for cursor Load more; states are loading, empty (no entries / no matches with `-- clear filters --`), error (with reference and `-- retry --`) and unauthorized (`Permission denied`).

Activating a row (click, Enter or Space) opens a **detail side sheet** (new `components/ui/sheet.jsx`, normal app theme, focus trap, Escape and close button, focus returns to the row) with action, time, result, actor, resource, correlation ID, IP address and the changes and metadata JSON. The inline "Details" disclosure was removed.

**Export is NOT built (still Planned).** There is no export button, client-side export or export endpoint; nothing was added for it.
