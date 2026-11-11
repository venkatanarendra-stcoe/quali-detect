# @qmentisai/db

Central Prisma schema, migrations, seed, client and repository base (PostgreSQL). Authorization semantics: `docs/AUTHORIZATION.md`; entity groups: `docs/technical/DATABASE_DESIGN.md`.

## Schema (`prisma/schema/*.prisma`, 25 tables)

| File                  | Tables                                                                                                                                                                                                                                       |
| --------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `platform.prisma`     | `tenants`, `subscription_plans`, `plan_versions`, `entitlement_catalog`, `plan_entitlements`, `tenant_subscriptions`, `tenant_entitlements`, `quota_definitions`, `tenant_quotas`, `platform_roles`, `platform_users`, `platform_audit_logs` |
| `identity.prisma`     | `users` (global), `tenant_memberships`, `groups`, `group_members`, `permissions`, `roles`, `role_permissions`, `user_role_assignments`, `group_role_assignments`, `sessions`, `audit_logs`                                                   |
| `organization.prisma` | `workspaces`, `workspace_members`                                                                                                                                                                                                            |

Conventions: UUID ids, `timestamptz` timestamps (`createdAt`/`updatedAt`), camelCase fields mapped to snake_case columns, PascalCase models mapped to the table names above, enums mapped to snake_case types.

**Tenant ownership.** Tenant-owned tables carry an explicit non-null `tenantId` indexed first: `tenant_subscriptions`, `tenant_entitlements`, `tenant_quotas`, `tenant_memberships`, `groups`, `group_members`, `user_role_assignments`, `group_role_assignments`, `workspaces`, `workspace_members`, `audit_logs`. `roles` and `role_permissions` have a nullable `tenantId` (NULL = built-in, set = custom). `users`, `permissions`, `sessions` (which carries `activeTenantId`) and the platform tables are not tenant-owned.

**Cross-tenant integrity in the database.** Parent-child links inside a tenant are composite foreign keys on `(tenantId, id)`; for example a `group_members` row, a role assignment or a workspace member cannot reference another tenant's group or workspace, and a user must have a `tenant_memberships` row in the same tenant. These are verified by running the migration on PostgreSQL 18 (see below).

**Authorization decisions encoded.** Users are global with `tenant_memberships`; user and group assignments are separate tables with nullable `expiresAt` (expired assignments are ignored by the resolver, nothing deletes them); no deny rows (grant-only); flat groups; the session carries the active tenant; platform users and roles are a separate store (`platform_roles.permissions` holds `platform.*` keys, one role per platform user in v1).

**`scopeKey` and CHECK constraints.** `user_role_assignments` / `group_role_assignments` store `scopeKey` (`"tenant"` or the workspace id) so that uniqueness is exact (NULL `workspaceId` would not be unique in PostgreSQL). Hand-written CHECK constraints in the migration enforce scope/workspace/scopeKey consistency, lowercase emails, and role ownership (built-in: no tenant and `ownerKey = built-in`; custom: one tenant). Prisma ignores CHECK constraints, so `migrate dev` does not drop them.

## Migrations and seed

Migration `20261111190000_quota_usage_and_audit_immutability` adds `tenant_quota_usage` (atomic quota counters) and PostgreSQL triggers that reject UPDATE, DELETE and TRUNCATE on `audit_logs` and `platform_audit_logs`; users with audit rows therefore cannot be hard-deleted (deactivate them instead).

- `20261111000000_init_placeholder`: empty placeholder (kept for history).
- `20261111120000_platform_identity_foundation`: all tables, indexes, foreign keys and the CHECK constraints.
- Seed (`prisma/seed.js`, idempotent): the permission catalog (81 keys from `@qmentisai/shared`), the 7 built-in roles with their bundles, the platform roles (Super Admin, Support), **one platform super admin** (`superadmin@qmentis.example`), and a demo tenant (`demo`) with 2 workspaces (Payments Platform, Identity & Access), 7 users (one per built-in role, `demo.<role>@demo.example`), a _Security Team_ group that grants Security Analyst in the second workspace, and a _Release Engineers_ group with members but no assignment. **No credentials are seeded** (password hashes are NULL): nobody can sign in until the identity module exists.

```bash
cp .env.example .env          # set DATABASE_URL (a dedicated dev database; the role needs CREATE rights for migrate dev)
pnpm --filter @qmentisai/db db:migrate:deploy   # apply migrations (or db:migrate:dev while developing)
pnpm --filter @qmentisai/db db:seed
pnpm --filter @qmentisai/db db:migrate:status
```

`prisma.config.js` loads `packages/db/.env` when present. Keep applied migration history intact; add new migrations instead of editing old ones.

## Client and repositories

| Export                                           | Purpose                                                                   |
| ------------------------------------------------ | ------------------------------------------------------------------------- |
| `getDbClient(options?)` / `disconnectDbClient()` | process-wide Prisma client (one pool per process; survives watch reloads) |
| `createDbClient(options?)`                       | separate client for scripts and isolated checks                           |
| `pingDatabase(client)`                           | readiness probe (`SELECT 1`)                                              |
| `withTransaction(client, fn, options?)`          | transaction helper (timeouts, joins an existing transaction)              |
| `createTenantRepository({ model, getClient })`   | base repository for **tenant-owned** models                               |
| `createPlatformRepository({ model, getClient })` | base repository for platform-owned models only                            |

**Tenant rule.** Tenant-owned records are never queried by id alone. Every `createTenantRepository` method requires `tenantId` as its first argument and injects it into `where`/`data`; passing `tenantId` inside `where` or `data` throws; `update`/`delete` match id **and** tenant and return `null`/`false` otherwise. `tenantId` must come from the trusted request or job context. Model delegate names are camelCase (`userRoleAssignment`, `workspace`, ...).

## Deviations from `DATABASE_DESIGN.md`

- Added `tenant_memberships` (needed because users are global) and `permissions` is a code-mirrored table.
- Plan versions have no price columns and quotas no enforcement column (commercial values and quota policy are open decisions).
- `createdBy`/`addedBy`/`invitedBy` columns are plain ids without foreign keys (history survives user removal).
- "One current subscription per tenant" and "a workspace-scope assignment also creates a workspace member row" are service rules (no partial unique index, which Prisma would try to drop).
- `finding_*`, `repositories`, `pipelines`, `scan_*` and other engineering tables are not modeled yet.
