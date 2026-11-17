# QmentisAI Frontend Architecture

## Stack

- JavaScript ES Modules.
- React.
- Vite.
- Tailwind CSS.
- shadcn/ui.
- React Router.
- TanStack Query.
- Zustand.
- React Hook Form.
- Zod.
- TanStack Table.
- Recharts.
- Lucide React.
- Sonner.

## Applications

Two independently runnable applications:
- `apps/tenant-web`
- `apps/root-console`

Each owns its routes, navigation, layouts, authentication context and feature modules. Share design tokens and suitable generic components through packages, but do not couple the applications' business navigation or permission models.

## Feature structure

```text
feature-name/
  components/
  pages/
  hooks/
  services/
  schemas/
  stores/
  constants/
  index.js
```

## State management

- TanStack Query: server state, caching, refetching and mutations.
- Zustand: local/global client state such as selected workspace or UI preferences.
- React Hook Form: form state.
- URL/search parameters: shareable filters and pagination when appropriate.

Avoid duplicating server state in Zustand.

## UI standards

- Use shadcn/ui as the base component system.
- Use Tailwind CSS and shared design tokens.
- Use accessible labels, keyboard interaction and clear focus states.
- Build reusable product components for severity, finding status, pipeline status, scan progress, SLA and quota indicators.
- Keep business rules on the backend.

## Authorization in the UI

The UI may hide or disable actions based on effective permissions for usability. The backend remains the enforcement point for every protected action.

## API communication

Use a shared API client with consistent authentication handling, error normalization, correlation IDs and cancellation support where appropriate.

## Authentication and authorization

Mock authentication and centralized RBAC are described in [`AUTHORIZATION.md`](AUTHORIZATION.md). Frontend checks are usability aids; the backend must enforce every request.

## Root Console navigation (apps/root-console)

Defined once in `@qmentisai/shared` (`PLATFORM_NAV_GROUPS`, `packages/shared/src/platform-navigation.js`) and evaluated by `evaluatePlatformNavigation` with the user's `platform.*` permissions only (the flat list from `GET /platform/me`). An item shows only if `implemented && permitted && route exists`; empty groups are hidden. The app adds labels, icons and URLs (`components/layout/nav.js`) and the route table (`app/routes.jsx`).

Separation from the Tenant Application is enforced, not just intended: the Root Console imports `@qmentisai/shared/platform` (platform navigation and the platform-only permission catalog, `platform-permissions.js`), never the package root; ESLint `no-restricted-imports` fails the build on the root import or on any tenant-web import, and the production bundle contains no tenant or workspace permission keys. The platform navigation module throws at load time if any item uses a non-`platform.*` key.

| Group | Item | Route | Permission |
|---|---|---|---|
| Platform | Platform dashboard | `/dashboard` | `platform.tenant.view` |
| Platform | System monitoring | `/monitoring` | `platform.monitoring.view` |
| Customers | Tenant management | `/tenants` | `platform.tenant.view` |
| Customers | Subscription management | `/subscriptions` | `platform.subscription.view` |
| Customers | License management | `/licenses` | `platform.license.view` |
| Customers | Feature entitlements | `/entitlements` | `platform.entitlement.view` |
| Customers | Usage & quotas | `/usage` | `platform.usage.view` |
| Platform administration | Platform users | `/platform-users` | `platform.user.view` |
| Platform administration | Integration catalog | `/integration-catalog` | `platform.integration_catalog.view` |
| Platform administration | Global configuration | `/config` | `platform.config.view` |
| Operations | Support & diagnostics | `/support` | `platform.support.request_access` |
| Operations | Platform audit logs | `/audit-logs` | `platform.audit_log.view` |

The permission mapping for the dashboard, subscriptions, usage and support items is **Recommended** (no dedicated key exists per screen). All pages except the dashboard shell are "Coming soon" placeholders reachable only with the permission. Platform Super Admin sees all 12 items; Platform Support sees 10 (everything except Platform users and Platform audit logs).

## Navigation architecture: Organization layout and Workspace layout

The application shell (`apps/tenant-web/src/app/layouts/app-layout.jsx`) chooses one of two layouts from the URL (`useNavContext`). Which items exist and who may see them is defined once in `@qmentisai/shared` (`ORG_NAV_GROUPS`, `WORKSPACE_NAV_GROUPS`) and evaluated by the central authorization engine; the app only adds labels, routes and icons (`components/layout/nav.js`). No navigation code checks role names.

> **Implementation note (2026-11-11).** The tables below keep their original wording, but permission keys follow the current catalog (`docs/AUTHORIZATION.md`): `tenant_user.view` became `user.view` (Users & Groups) and `role.view` (Roles & Permissions). The definitions live in `packages/shared/src/navigation.js` and are evaluated by `evaluateNavigation`. "Route exists" is the route table in `apps/tenant-web/src/app/routes.jsx`. `docs/TENANT_APP_WIREFRAME_SPEC.md` (T-00a, T-00b, T-01, T-05) does not exist in this repository: T-00a/T-00b were taken as the Organization/Workspace layouts below, T-01 as the login page and T-05 as the 403/404/error states.

### Organization layout (outside a workspace)

| Group | Item | Route | Permission (tenant scope) |
|---|---|---|---|
| Main | Organization Overview (**Admin only**: `dashboard.view` is in the Admin bundle only, 2026-11-17, Confirmed) | `/overview` | `dashboard.view` |
| Main | Workspaces | `/workspaces`, `/workspaces/new` | `workspace.view` (held in some workspace) |
| Administration | Users & Groups | `/users`, `/groups` | `tenant_user.view` |
| Administration | Integrations | `/integrations` | `integration.view` |
| Administration | Roles & Permissions | `/roles` | `tenant_user.view` |
| Administration | Organization Settings | `/settings` | `tenant_settings.view` |
| Administration | Audit Logs | `/audit-logs` | `audit_log.view_all` |

Administration is tenant-level: a Manager or a workspace Admin does not see it. Administration pages other than the overview are placeholders (planned modules), reached only by users who hold the permission. The Organization Overview lists the workspaces the user can access and links each to its dashboard.

### Workspace layout (inside `/workspaces/:workspaceId/...`)

The sidebar header shows "All workspaces" and the workspace switcher (active workspace name; a dropdown of accessible workspaces when there is more than one, a static label otherwise). Items are checked in the active workspace and shown only when their route exists:

| Group | Item | Route | Permission (in the workspace) |
|---|---|---|---|
| Workspace | Dashboard | `/workspaces/:id/dashboard` | `workspace.view` |
| Workspace | Repositories | `/workspaces/:id/repositories` | `repository.view` |
| Workspace | Pipelines | `/workspaces/:id/pipelines` | `pipeline.view` |
| Security | Policies | `/workspaces/:id/policies` | `policy.view` |
| Workspace Administration | Members & Groups | `/workspaces/:id/members` | `workspace.view` |
| Workspace Administration | Roles & Permissions | `/workspaces/:id/roles` | `workspace.view_roles` |
| Workspace Administration | Activity | `/workspaces/:id/activity` | `workspace.view_activity` |
| Workspace Administration | Settings | `/workspaces/:id/settings` | `workspace.update` |

Executions, Findings, Security Reviews, Approvals, Remediation, Reports and workspace Integrations are defined (`implemented: false`) but hidden until their modules exist; no placeholder pages are added for them. Repository details (`/repositories/:repositoryId/...`) and `/repositories/connect?workspace=:id` use the workspace layout of the repository's workspace.

Behavior: switching workspace keeps the current section (and dashboard filters) when the user may open it in the target workspace, otherwise opens the target Dashboard. Workspace pages are remounted per workspace and cache keys include the workspace id, so data from the previous workspace is never shown. **Amended 2026-11-16 (owner decision, Confirmed; supersedes "the account menu exists only in the top bar, no sidebar account area"):** there is no top bar in either app. The sidebar carries the logo, the organization (and workspace switcher in the Workspace layout), Notifications with its unread badge and the navigation. **Revised 2026-11-17 (owner decision, Confirmed):** Account is a normal navigation item (`account`, scope `self`, no permission) in the last group "You" of both layouts, followed by a Sign out row; the bottom-pinned account block and the search / command palette trigger were removed (the palette component stays in the repo, unused, global shortcut disabled). The Account page links to Settings (Appearance, Preferences), Switch organization (tenant, when applicable) and Sign out. Root Console keeps its environment strip and violet dark sidebar, moves the system-status indicator into the sidebar and has no accent picker. **Landing (2026-11-17, owner decision, Confirmed; replaces the withdrawn default-workspace preference):** `/` and the post-login redirect are a client-side rule on permissions from the authorization engine, never role names: a holder of `dashboard.view` (Admin only today) goes to `/overview`, everyone else to `/workspaces` (the Workspaces list, whose empty state covers a user with no accessible workspace). There is no per-user default and no landing endpoint. Navigation is still defined once in `@qmentisai/shared` and evaluated by the authorization engine; the Account item is the user's own page and needs no permission (the engine still evaluates it for every authenticated principal). `AppPageLayout`/`WizardLayout` default offset is 3rem (page padding) plus the shell's `--app-shell-extra` (the 3rem mobile menu strip below 768 px).

Legacy routes: `/workspaces/:id` redirects to `/dashboard`, `/workspaces/:id/edit` to `/settings`, `/repositories` to the repositories page of the last or first accessible workspace.

### Workspace Dashboard

`/workspaces/:workspaceId/dashboard` always shows the active workspace (no workspace filter). Filters: period, severity (chart bar click, or severity toggles in Table view), Refresh, and a mutually exclusive Chart view / Table view (`period`, `sev`, `view` in the URL; default chart). `dashboardService.overview({ workspaceId, period, severities })` verifies access independently (404 not accessible, 403 not permitted). Chart view: severity, lifecycle, workload, execution trend, connection health and SLA charts plus the posture/KPI row. Table view: findings, pipelines, repositories, workload and SLA, and activity sections, each its own table scrolling inside its card.
