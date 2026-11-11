# Module specification: Access management (authorization engine and directory CRUD)

Status: **Implemented 2026-11-11** in `apps/api` and `@qmentisai/shared`. Rules come from `docs/AUTHORIZATION.md` (Confirmed decisions 1-6; everything else there is Recommended). Items marked **Recommended — default applied** are choices made here that you can revisit.

## 1. Scope
Central authorization engine (pure, shared by API and frontends), API enforcement (`authorize`), audit service, entitlement/quota helpers, and CRUD for users, groups, roles, role assignments, workspaces and workspace members. Out of scope: SSO/MFA, SoD checks on approvals (no findings yet), Root Console tenant lifecycle endpoints (the audit actions exist), Socket.IO room updates, event publishing (no outbox yet), permission caching.

## 2. Engine (`packages/shared/src/authorization.js`, pure)
| Function | Purpose |
|---|---|
| `resolveEffectivePermissions(context, workspaceId?)` | Direct + group assignments, tenant + workspace scope, expiry, flat groups, preconditions (active user, usable tenant, **active** membership) -> `{ tenant, allWorkspaces, workspaces[] }` |
| `can(permissions, key, scope)` | `scope` = `{type:"tenant"}`, `{type:"workspace",workspaceId}` or `{type:"platform"}`; unknown key or key/scope mismatch **throws** (programming error), absence returns false |
| `canInAnyWorkspace`, `visibleWorkspaceIds` | Navigation/filtering helpers |
| `partitionPermissionKeys`, `findUngrantableKeys`, `isTenantAdministrator` | Escalation guard (§5.6, SOD-3) |

No role names anywhere. "Tenant administrator" is capability-based: holds `role.manage` **and** `role_assignment.manage_tenant`; such callers may grant keys they lack (decision 5) but never to themselves. **Recommended — default applied.**

## 3. Enforcement (`apps/api`)
- Every route declares `config.audience`; tenant routes add `preHandler: app.authz.authorize(key, scopeResolver)`.
- `authorize` loads the resource with the session's tenant filter (nothing -> 404), hides workspaces the caller cannot see (same 404), then `can()` (false -> 403). Key and resolver scope are validated at startup. Tenant-level collections answer 403; workspace-data collections return only visible items.
- Permissions are resolved per request (no cache), so changes apply on the next request.
- Invariants: tenant keeps >= 1 administrator (409 `LAST_TENANT_ADMIN`); workspace keeps >= 1 administrator assignment (409 `CONFLICT`, `details.reason: last_workspace_administrator`); both serialized with advisory locks and rolled back on violation.
- 403 bodies never name permissions (Q13 stays Open); `ROLE_ESCALATION` returns `missingCount` only.

## 4. Audit (`apps/api/src/audit`)
`audit.tenant.record(entry, { tx })` / `audit.platform.record(...)` are **strict** and run in the same transaction as the change; `recordSafe` is best effort (sign-in). Rows are immutable: no update/delete API and PostgreSQL triggers reject UPDATE/DELETE/TRUNCATE on `audit_logs` and `platform_audit_logs` (a user with audit rows therefore cannot be hard-deleted). Non-UUID correlation ids are kept in `metadata.requestId`. Action names: `audit/actions.js` (includes tenant lifecycle and sensitive-export actions for the upcoming modules).

## 5. Entitlements and quotas (`apps/api/src/entitlements`, `app.entitlements`)
`checkEntitlement`, `assertEntitlement`, `assertWithinLimit` (count limits such as `workspaces.max`, `users.max`, called inside the creating transaction after an advisory lock) and `consumeQuota` / `releaseQuota` (atomic conditional SQL on new table `tenant_quota_usage`). A separate gate after authorization; never grants permissions. **Recommended — default applied:** a key absent from the catalog is ungoverned (allowed); a governed key resolves tenant override, then the tenant's current trial/active subscription, else disabled; a governed quota without a configured limit is refused. Errors: 403 `ENTITLEMENT_REQUIRED`, 403 `QUOTA_EXCEEDED`.

## 6. API (all under `/api/v1`, tenant session)
| Endpoint | Permission (scope) | Notes |
|---|---|---|
| `GET/POST /users`, `GET/PATCH/DELETE /users/{id}`, `GET /users/{id}/effective-permissions` | `user.view` / `user.manage` (tenant) | Tenant view = membership. Invite creates an `invited` membership (+ the global user if new); name hidden until accepted; seat limit `users.max` |
| `GET /me/invitations`, `POST /me/invitations/{tenantId}/accept` | authenticated | **Recommended — default applied:** the invitee must accept; avoids attaching existing accounts without consent and avoids revealing whether an email has an account |
| `GET/POST /groups`, `GET/PATCH/DELETE /groups/{id}`, `GET /groups/{id}/members`, `PUT/DELETE /groups/{id}/members/{userId}` | `group.view` / `group.manage` (tenant) | Adding a member is escalation-checked against the group's assignments |
| `GET /permissions`, `GET/POST /roles`, `GET/PATCH/DELETE /roles/{id}` | `role.view` / `role.manage` (tenant) | Custom roles only editable; clone built-ins; delete blocked while assigned (409 `ROLE_IN_USE`); key diff audited |
| `GET/POST /role-assignments`, `PATCH/DELETE /role-assignments/{id}` | `role.view` / `role_assignment.manage_tenant` (tenant) | Tenant scope. Reactivating/extending is re-checked for escalation |
| `GET/POST /workspaces/{id}/role-assignments`, `PATCH/DELETE …/{assignmentId}` | `workspace.view_roles` / `workspace.manage_members` (workspace) | Adds the user to the roster |
| `GET/POST /workspaces`, `GET/PATCH /workspaces/{id}`, `POST …/archive`, `POST …/restore` | list: visible only; `workspace.create` (tenant); `workspace.view` / `workspace.update` / `workspace.archive` (workspace) | Creator becomes workspace administrator; plan limit `workspaces.max` (archived workspaces do not count); archived = read-only. No hard delete (no permission key defines one) |
| `GET /workspaces/{id}/members`, `PUT/DELETE …/members/{userId}` | `workspace.view` / `workspace.manage_members` (workspace) | Removing a member also deletes their workspace-scope assignments there |

Deviations from `docs/AUTHORIZATION.md` §8: `GET /me/permissions` is in the identity module; assignment creation has **no Idempotency-Key** yet (a repeat returns 409 `CONFLICT` thanks to the unique constraint). New error codes added to `@qmentisai/contracts`: `LAST_TENANT_ADMIN`, `ROLE_IN_USE`, `ROLE_ESCALATION`, `ENTITLEMENT_REQUIRED`, `QUOTA_EXCEEDED`.

## 7. Open items
Q13 (naming permissions in 403 bodies); permission caching and invalidation; Idempotency-Key header; group assignment cleanup when a group is emptied; email delivery of invitations; whether suspended memberships should keep workspace rosters.
