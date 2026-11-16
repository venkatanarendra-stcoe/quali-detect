# Authorization and Mock Authentication

**Status:** Implemented for the mock-data frontend (Phase 8). **Not a security boundary.**
**Code:** `packages/shared/src/authorization/` (engine), `packages/mock-services/src/auth.js` (session and service guards), `apps/tenant-web/src/features/auth/` and `features/authorization/` (UI).
**Related:** `TENANT_ISOLATION.md`, `docs/decisions/ADR-003-TENANT-ISOLATION.md`, `docs/technical/SECURITY_GUIDELINES.md`.

> **Update 2026-11-11:** the mock services, seeded accounts and browser tests described below were removed (backup outside the repo). The engine, role definitions and navigation rules in `packages/shared` remain; sections about seeded accounts and mock-service guards describe the removed prototype and are kept as the specification to re-implement in the backend.

## 1. Boundaries (read first)

- Mock authentication is **not** production authentication. The session token is a mock string in `localStorage`; the demo password is shared and stored in plain text in mock data. There is no hashing, OAuth, SSO, JWT or MFA.
- Frontend and mock-service RBAC is **not a security boundary**. The real backend must independently validate identity, tenant, workspace ownership and permission on **every** protected request, enforce tenant and workspace isolation, and write audit logs.
- Super Admin belongs to the Root Console (separate platform permissions, ADR-003). It is not implemented here.
- No registration, password recovery or invitation acceptance exists. Accounts are seeded.

## 2. Model

Inputs to every decision (`authorize(ctx, permission, { workspaceId })`):

| Input | Source |
|---|---|
| Authenticated user, status | session |
| Tenant role (`user.tenantRole`) | user record |
| Direct workspace assignments | workspace memberships of type `user` |
| Group assignments | memberships of type `group`, expanded for the groups the user belongs to |
| Resource workspace | the workspace that owns the resource |

Rules:

1. **Permissions are `resource.action` ids** from one registry (`permissions.js`). Components never check role names.
2. **Two scopes.** `tenant` permissions (e.g. `workspace.create`, `tenant_user.manage`) come only from the tenant role. `workspace` permissions are evaluated per workspace from active assignments in that workspace.
3. **Only the tenant Admin is tenant-wide** for workspace permissions (every workspace). A tenant Manager, Lead, etc. gets only the tenant-scope permissions of its role (Manager: `workspace.create` only since 2026-11-17, when `dashboard.view` became Admin-only, see docs/AUTHORIZATION.md decision 30; no tenant administration) and reaches data only through assignments. This **replaces** the earlier prototype rule that treated Manager as tenant-wide (deviation, see section 8).
4. **Workspace Admin is not tenant Admin.** A workspace Admin assignment grants every workspace-scope permission in that workspace only.
5. **Group membership alone grants nothing.** Only a group that holds a workspace role assignment produces an assignment for its members (seed: *Release Engineers* has no assignment).
6. **Inactive grants are ignored:** non-`active` assignments and non-`active` users (suspended, invited) get no permissions and cannot sign in.
7. **Deny wins.** An assignment may carry `deniedPermissions`; they are subtracted from the union of grants for that workspace, including a tenant Admin's. No seeded deny exists yet; the engine and tests support it.
8. **No privilege escalation.** A member manager can grant, change or remove only roles whose workspace permissions they already hold (`canGrantRole`), enforced in the service and by disabling options in the UI.
9. **Hidden, not leaked.** A resource in a workspace the user cannot see returns `404 RESOURCE_NOT_FOUND` ("not found or not accessible"). A visible resource without the permission returns `403 FORBIDDEN`. No session returns `401 UNAUTHENTICATED`.
10. **Repositories restricted to groups** (repository access mode *restricted*) are hidden from members outside those groups unless they hold `repository.manage_access`.
11. **Last tenant Admin protection:** `userService.setTenantRole` and `suspend` return `409 LAST_TENANT_ADMIN` when they would leave no active Admin (`wouldRemoveLastAdmin`). A workspace must also keep one Admin (existing `LAST_ADMIN` rule). There is no Users UI yet.

## 3. APIs

| API | Where | Use |
|---|---|---|
| `authorize(ctx, permission, resource)` / `can` | `@qmentisai/shared` | Single decision function (UI and mock services) |
| `getEffectivePermissions(ctx, resource)` | shared | Set of permissions for a workspace |
| `getAccessibleWorkspaceIds`, `workspacesWith`, `hasPermissionAnywhere`, `canGrantRole`, `wouldRemoveLastAdmin` | shared | Scoping and guards |
| `useAuth()` | `features/auth` | status, user, tenant, workspace roles, login, logout |
| `usePermissions(workspaceId)` / `useCan(permission, { workspaceId })` | `features/authorization` | `can`, `canAnywhere`, `canGrantRole` |
| `ProtectedRoute`, `PermissionGate`, `AccessDenied` | `features/authorization` | Route guard, disabled-with-reason controls, denied state |
| `assertCan`, `assertWorkspaceResource`, `visibleWorkspaceIds`, `workspaceIdsWith`, `requireContext` | `mock-services/src/auth.js` | Guards used inside every protected service |

Navigation visibility and route guards share `features/authorization/constants/navigation.js`.

## 4. Roles and permission matrix

Tenant-scope columns apply to the tenant role; workspace-scope columns apply per workspace. Source of truth: `role-definitions.js` (each role has a `rationale`). The product docs do not define a matrix, so these are **proposed mappings** to confirm. `Auditor` is the seeded tenant-defined custom role.

| Permission | Scope | Admin | Manager | Lead | Security Analyst | Dev Lead | Developer | Guest / Viewer | Auditor |
|---|---|:-:|:-:|:-:|:-:|:-:|:-:|:-:|:-:|
| `dashboard.view` | tenant | ✓ | | | | | | | |
| `workspace.view` | workspace | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| `workspace.create` | tenant | ✓ | ✓ |  |  |  |  |  |  |
| `workspace.update` | workspace | ✓ | ✓ |  |  |  |  |  |  |
| `workspace.archive` | workspace | ✓ | ✓ |  |  |  |  |  |  |
| `workspace.manage_members` | workspace | ✓ | ✓ |  |  |  |  |  |  |
| `workspace.view_roles` | workspace | ✓ | ✓ |  |  |  |  |  |  |
| `workspace.view_activity` | workspace | ✓ | ✓ | ✓ | ✓ | ✓ |  |  | ✓ |
| `policy.view` | workspace | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| `policy.manage` | workspace | ✓ | ✓ |  |  |  |  |  |  |
| `repository.view` | workspace | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| `repository.connect` | workspace | ✓ | ✓ |  |  | ✓ |  |  |  |
| `repository.sync` | workspace | ✓ | ✓ | ✓ |  | ✓ |  |  |  |
| `repository.toggle` | workspace | ✓ | ✓ | ✓ |  |  |  |  |  |
| `repository.update` | workspace | ✓ | ✓ |  |  | ✓ |  |  |  |
| `repository.manage_access` | workspace | ✓ | ✓ |  |  |  |  |  |  |
| `repository.disconnect` | workspace | ✓ | ✓ |  |  |  |  |  |  |
| `pipeline.view` | workspace | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| `pipeline.manage` | workspace | ✓ | ✓ | ✓ |  | ✓ |  |  |  |
| `execution.view` | workspace | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| `execution.run` | workspace | ✓ | ✓ | ✓ |  | ✓ |  |  |  |
| `finding.view` | workspace | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| `security_review.view` | workspace | ✓ | ✓ | ✓ | ✓ |  |  |  |  |
| `finding.review` | workspace | ✓ |  |  | ✓ |  |  |  |  |
| `approval.view` | workspace | ✓ | ✓ | ✓ |  |  |  |  |  |
| `approval.approve` | workspace | ✓ |  | ✓ |  |  |  |  |  |
| `approval.reject` | workspace | ✓ |  | ✓ |  |  |  |  |  |
| `remediation.view` | workspace | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |  |  |
| `finding.assign` | workspace | ✓ |  |  |  | ✓ |  |  |  |
| `finding.remediate` | workspace | ✓ |  |  |  | ✓ | ✓ |  |  |
| `report.view` | workspace | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| `report.export` | workspace | ✓ | ✓ | ✓ |  |  |  |  | ✓ |
| `audit_log.view` | workspace | ✓ |  |  |  |  |  |  | ✓ |
| `audit_log.view_all` | tenant | ✓ |  |  |  |  |  |  |  |
| `integration.view` | tenant | ✓ |  |  |  |  |  |  |  |
| `integration.manage` | tenant | ✓ |  |  |  |  |  |  |  |
| `tenant_user.view` | tenant | ✓ |  |  |  |  |  |  |  |
| `tenant_user.manage` | tenant | ✓ |  |  |  |  |  |  |  |
| `tenant_settings.view` | tenant | ✓ |  |  |  |  |  |  |  |
| `tenant_settings.manage` | tenant | ✓ |  |  |  |  |  |  |  |

Distinctions kept separate: view, review (`finding.review`), approve (`approval.approve`/`reject`), assign (`finding.assign`) and remediate (`finding.remediate`); view and connect/disconnect repositories; workspace and tenant administration.

Proposed-mapping notes: Developer remediation is not yet limited to *assigned* findings (Findings module not built); Dev Lead cannot disconnect repositories or manage members/policies; Lead can start and toggle pipelines but not review or assign; Manager cannot review, approve or remediate.

## 5. Seeded accounts (local development only)

Shared demo password: `Qmentis!Demo1`. Sign in at `/login`, or use the clearly labelled demo selector (it signs in as the real seeded identity; it grants nothing by itself). Suspended and invited users are rejected (Jonas Weber, Ravi Patel). Tenant Admin Alex Park also holds a redundant Security Analyst group assignment; as Admin they can access every workspace.

| Name | Email | Tenant role | Workspace access (workspace: role via source) |
|---|---|---|---|
| Alex Park | alex.park@acme.example | Admin | Payments Platform: Security Analyst (via Security Team); Identity & Access: Security Analyst (via Security Team); Checkout Experience: Security Analyst (via Security Team) |
| Priya Raman | priya.raman@acme.example | Manager | Payments Platform: Admin, Manager (via Platform Leads); Legacy Billing: Admin |
| Marcus Lee | marcus.lee@acme.example | Security Analyst | Payments Platform: Security Analyst, Security Analyst (via Security Team); Identity & Access: Security Analyst (via Security Team); Checkout Experience: Security Analyst (via Security Team); Mobile Apps: Developer |
| Dana Whitfield | dana.whitfield@acme.example | Dev Lead | Payments Platform: Manager (via Platform Leads), Developer (via Payments Devs); Mobile Apps: Dev Lead |
| Sofia Alvarez | sofia.alvarez@acme.example | Developer | Payments Platform: Developer (via Payments Devs) |
| Kenji Mori | kenji.mori@acme.example | Developer | Payments Platform: Developer (via Payments Devs) |
| Amara Okafor | amara.okafor@acme.example | Lead | Payments Platform: Lead, Security Analyst (via Security Team); Identity & Access: Security Analyst (via Security Team); Checkout Experience: Security Analyst (via Security Team); Data Platform: Lead; Mobile Apps: Guest / Viewer |
| Liam O'Brien | liam.obrien@acme.example | Developer | Identity & Access: Developer (via Identity Devs); Checkout Experience: Developer |
| Noor Haddad | noor.haddad@acme.example | Manager | Payments Platform: Manager (via Platform Leads); Identity & Access: Admin |
| Tomás Novak | tomas.novak@acme.example | Dev Lead | Identity & Access: Developer (via Identity Devs), Dev Lead; Checkout Experience: Admin |
| Hana Kim | hana.kim@acme.example | Guest / Viewer | Payments Platform: Guest / Viewer; Internal Tools: Auditor (via Auditors), Guest / Viewer |
| Elena Petrova | elena.petrova@acme.example | Security Analyst | Payments Platform: Security Analyst (via Security Team); Identity & Access: Security Analyst (via Security Team); Checkout Experience: Security Analyst (via Security Team) |
| Grace Nwosu | grace.nwosu@acme.example | Developer | Mobile Apps: Admin |
| Chen Wei | chen.wei@acme.example | Developer | Data Platform: Developer (via Data Engineers) |
| Isabel Costa | isabel.costa@acme.example | Dev Lead | Payments Platform: Manager (via Platform Leads); Data Platform: Admin, Developer (via Data Engineers) |
| Omar Farouk | omar.farouk@acme.example | Developer | Payments Platform: Developer (via Payments Devs); Data Platform: Developer (via Data Engineers); Internal Tools: Admin |


Scenarios covered: Marcus Lee is Security Analyst in Payments and Developer in Mobile Apps; Amara Okafor is Lead in Payments and Data Platform but Viewer in Mobile Apps; Sofia Alvarez and Kenji Mori reach only Payments (Kenji is also in the role-less Release Engineers group); Hana Kim is a Guest with read-only access (plus Auditor in Internal Tools via a group); Dana Whitfield is Manager in Payments through the Platform Leads group and Dev Lead in Mobile Apps.

## 6. Authentication flow (mock)

`/login` validates email and password, shows invalid-credential, inactive-account and server-error feedback, a loading state and a `next` redirect (same-origin paths only). `AuthBootstrap` restores a stored token on refresh (`sessionService.restore`: format, 8 h expiry, active user). Any `401` expires the session and returns to `/login`. Logout clears the token and the query cache. Switching user clears cached data so one user's data is never shown to another. The previous `?role=` override and the "act as role" menu were **removed**; permissions come only from the authenticated user's assignments. `?mock=error|empty` and `?latency=` still work.

## 7. Navigation and route guards

Navigation is defined in `packages/shared/src/authorization/navigation.js` and evaluated by the same engine as every other decision: `ORG_NAV_GROUPS` (organization layout, tenant-scope permissions only), `WORKSPACE_NAV_GROUPS` (workspace layout, evaluated in the active workspace, `implemented: false` entries never shown), `NAV_PERMISSIONS` (route guards for planned modules). The full item/permission tables are in `FRONTEND_ARCHITECTURE.md` (Navigation architecture). Unknown items are denied; groups with no accessible item are removed.

Key rules: only the tenant Admin sees organization Administration (Users & Groups, Integrations, Roles & Permissions, Organization Settings, Audit Logs); a workspace Manager or Admin gets workspace administration (Members & Groups, Roles & Permissions, Activity, Settings) only inside assigned workspaces; the same user can see a different workspace sidebar per workspace.

## 8. What is protected

- **Routes:** every app route requires sign-in; `ProtectedRoute` guards by permission (e.g. `/workspaces/new` needs `workspace.create`, `/repositories/connect` needs `repository.connect` in some workspace, planned modules use the navigation map). Workspace and repository layouts hide tabs the user cannot use and show an access-denied state for the active tab.
- **Navigation:** items are hidden when the view permission is not held anywhere.
- **Workspace Dashboard:** `dashboardService.overview({ workspaceId, period, severities })` requires `dashboard.view` and a workspace id. The id is a filter, not a grant: a workspace the caller cannot see returns 404, a missing id is a validation error (there is no all-workspaces aggregate), and each widget only counts data the caller may view in that workspace. The workspace comes from the route, never from a UI filter.
- **Services:** `workspaceService`, `repositoryService`, `policyService`, `pipelineService`, `executionService`, `findingService`, `activityService`, `dashboardService`, `providerService`, `userService`, `groupService` and `sessionService` all evaluate the signed-in user. Mutations require the specific permission (`workspace.update`, `workspace.archive`, `workspace.manage_members`, `policy.manage`, `repository.update|toggle|disconnect|sync|manage_access|connect`, `pipeline.manage`, `tenant_user.manage`, `workspace.create`).

## 9. Deviations, limitations, open decisions

- Manager is no longer implicitly tenant-wide (rule 3). A manager who creates a workspace for someone else is added as its Admin so they keep access.
- Role permission mappings are proposals pending product confirmation; no deny assignments are seeded; Developer "assigned findings only" and per-resource approvals await the Findings modules.
- Directory lookups (user and group search) need a reason to browse people (member management, workspace or repository editing, tenant user view).
- Sessions are in module memory plus a `localStorage` token, so a mock-data reset keeps the session; the token cannot be revoked server-side.
- Audit logging of permission and role changes is a backend responsibility; the mock only appends activity events.

## 10. Tests

`pnpm test` runs `node --test` suites: `packages/shared/tests/authorization.test.js` (engine) and `packages/mock-services/tests/identity-and-rbac.test.js` (login, restore, logout, unauthenticated access, per-workspace roles, group assignments, developer and guest restrictions, cross-workspace denial, escalation, restricted repositories, last-Admin protection). Navigation RBAC and dashboard filtering are covered by `packages/shared/tests/navigation.test.js` and `packages/mock-services/tests/dashboard.test.js`. `pnpm --filter @qmentisai/tenant-web test:e2e` runs headless-Chrome suites (`apps/tenant-web/e2e/`: navigation RBAC for all seven roles, direct URL access, workspace selection and URL persistence, chart rendering, empty/loading/error states, three viewport widths in both themes). It starts its own Vite server on port 5199 and needs Chrome (`CHROME_PATH`, default `/usr/bin/google-chrome`).
