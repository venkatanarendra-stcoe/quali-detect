# QmentisAI Development Progress Tracker

Update this file as implementation progresses. Use `Not Started`, `In Progress`, `Blocked`, `Completed` or `Deferred`.

| Workstream | Status | Notes / linked PR or commit |
|---|---|---|
| Monorepo foundation | Completed | Phase 1 (2026-11-11): pnpm workspace + Turborepo skeleton (apps/api, workers, tenant-web, root-console; packages/shared, contracts, db, ui, config). `pnpm install`, `pnpm lint`, `pnpm build` pass; skeletons only. |
| Shared contracts and validation | Not Started | |
| Fastify backend bootstrap | In Progress | Phase 2 part 1 (2026-11-11): apps/api bootstrap, Zod config, Pino + correlation id + redaction, central error handler/envelopes, OpenAPI, /health and /ready, validation and pagination helpers, reference `system` module. Prisma/Redis/RabbitMQ abstractions, auth and tenant context not started. |
| Prisma and database foundation | In Progress | Phase 3.1 (2026-11-11): platform + identity/organization schema (25 tables), migration `20261111120000_platform_identity_foundation`, idempotent seed. Migration and seed verified on a throwaway local PostgreSQL 18 cluster (since removed); NOT yet run on your database (no `packages/db/.env`). No engineering/findings tables yet. |
| Redis abstraction | In Progress | `@qmentisai/infra`: tenant-scoped cache, lock manager, rate limiter, idempotency store; key builders in `@qmentisai/shared`. Verified live against local Redis (cache isolation, TTL, locks, rate limit, idempotency). |
| RabbitMQ abstraction | In Progress | `@qmentisai/infra`: connection, publisher, consumer, retry classification/backoff, retry tiers, DLQ, idempotency; job envelope in `@qmentisai/contracts`. Logic verified with a simulated channel only: RabbitMQ is not installed/running here, so no live broker verification yet. |
| Authentication and sessions | In Progress | Mock provider, cookie sessions, /me, platform auth with mandatory platform MFA (mock) (2026-11-11); real SSO/MFA providers and tenant MFA policy pending |
| Tenant context and isolation | In Progress | Session-derived tenant context plugin done; every tenant route is gated by `authorize(...)` (tenant-filtered resource load, 404/403 rule). Cache/lock/room scoping for future modules pending |
| Authorization and roles | In Progress | Spec `docs/AUTHORIZATION.md` reviewed with decisions applied (2026-11-11); permission catalog and built-in role bundles in `@qmentisai/shared`; data model in `packages/db`. Engine in `@qmentisai/shared`, `authorize` enforcement, roles/assignments/groups APIs implemented 2026-11-11 (see `docs/modules/access-management/SPEC.md`). SoD on approvals and permission caching pending. |
| Entitlement enforcement | In Progress | Helpers `checkEntitlement` / `assertWithinLimit` / `consumeQuota` / `releaseQuota` (atomic usage in `tenant_quota_usage`), used by workspace creation and user invitation. Root Console plan/quota management not started. |
| Tenant frontend foundation | In Progress | 2026-11-11: Vite + React + Tailwind v4 + shadcn-style components, tokens in `@qmentisai/ui`, API client, auth + route guards, Organization/Workspace shells with central-engine navigation, PermissionGate, 403/404/error states. Verified in headless Chrome as all 7 seeded roles. Remaining screens are placeholders; no tests committed. |
| Root Console foundation | In Progress | 2026-11-11: separate Vite app (port 5174) with the Root violet / dark-sidebar theme, environment strip, platform login + mandatory MFA (mock, enforced server-side), `PLATFORM_NAV_GROUPS` evaluated with `platform.*` keys only, `SupportAccessBanner` component, import guard against tenant code. Verified in headless Chrome as Platform Super Admin and Platform Support. Screens R-04 tenants list, R-05 provision tenant, R-06 tenant detail with typed-confirmation lifecycle (suspend, reactivate, deactivate) implemented 2026-11-11 against new `platform-tenants` APIs. Other modules are placeholders; support-access grants, subscription/license/entitlement management and the platform audit viewer not built. |
| Worker entry points | In Progress | Six workers wired to the consumer with a no-op handler and graceful shutdown (`start:<worker>` scripts). Fail-fast config and broker-unreachable exit verified; live consumption not verified (no broker). |
| Organization and workspace | In Progress | Users, groups, workspaces, workspace members APIs (2026-11-11) and the screens T-06 overview, T-07 workspaces, T-08 create (policies step pending), T-40 members & groups, T-44 settings, verified in headless Chrome. Users/groups/roles administration screens, tenant settings, directory search endpoint, audit-log read API not started. |
| Repository integrations | Not Started | |
| Pipeline management | Not Started | |
| Execution orchestration | Not Started | |
| Repository analysis | Not Started | |
| Scan engine integration | Not Started | |
| Finding lifecycle | Not Started | |
| Review and approval workflow | Not Started | |
| Remediation and verification | Not Started | |
| Policies and governance | Not Started | |
| Reporting and notifications | Not Started | |
| Subscription and usage | Not Started | |

## Current sprint / task

- Objective: Code-first tenant UI with mock data (ADR-006): Workspace and Repository management.
- Owner: Frontend
- Status: Phases 1-5 implemented against mock services; Phase 6 validation run (2026-11-09): `pnpm build` passes, `pnpm lint` 0 errors / 1 warning (react-hook-form `watch` compiler notice), browser sweep of all Workspace and Repository routes at 1440/820/390 px plus `?mock=error|empty` showed no page errors or horizontal overflow. Not yet covered: automated tests, manual screen-reader pass.
- Relevant module specification: docs/design/TENANT_APPLICATION_DESIGN.md (3, 3b), ADR-006
- Open blockers: None for the frontend. Backend, real OAuth and authentication are out of scope until authorized.
- Phase 7 (2026-11-09): Tenant Overview dashboard implemented (`features/dashboard`, `dashboardService`). Build passes, lint clean (0 errors, 0 warnings). Playwright checks: filters (workspace, period, severity, clear, URL sync), navigation from tiles/rows/links, loading/empty/error states, scoping by the signed-in user, keyboard focus order, 1440/820/390 px with no overflow. Finding and execution detail links target `/findings/:id` and `/executions/:id`, which show the planned-module placeholder until those modules exist.
- Phase 8 (2026-11-09): mock authentication and centralized RBAC implemented (`docs/architecture/AUTHORIZATION.md`). `pnpm build` and `pnpm lint` pass (0 errors, 0 warnings); `pnpm test` runs 31 node tests (12 engine, 19 identity/RBAC service) with 0 failures. Browser checks (Playwright, headless Chrome): login/invalid/suspended/validation/redirect (including open-redirect block)/refresh restore/logout, then 11 users across 13 routes each plus a route sweep (overview, workspace and repository tabs) for 7 users at 1440 and 390 px with no page errors, overflow or unexpected logouts. Not yet covered: automated UI component tests, screen-reader pass.
- Phase 8.1 (2026-11-09): three defects reproduced and fixed. (1) Administration navigation: the Manager saw all five admin items because the Manager tenant role carried `tenant_user.view` and `integration.view`, and Guests/workspace Admins saw Audit Logs because it was gated by the workspace-scoped `audit_log.view`. Fixed with a tenant-only `audit_log.view_all`, Manager reduced to `dashboard.view` + `workspace.create`, and one shared `NAV_PERMISSIONS` map used by sidebar and route guards. (2) Overview aggregated "All workspaces" by default; it now takes an explicit `workspaceIds` selection (default: one workspace, multi-select, URL `ws=`, `ws=none` empty state, inaccessible ids rejected by the service and removed in the UI). (3) The Overview had no charts at all (CSS bars and lists only, zero Recharts SVGs); added severity, lifecycle and execution-trend charts plus a posture meter on filtered service data, with legends, tooltips, zero values and screen-reader tables. Tests: 49 node tests (20 shared, 29 mock-services) and 22 headless-Chrome tests (`pnpm --filter @qmentisai/tenant-web test:e2e`) pass; lint and build pass. Details in `docs/architecture/AUTHORIZATION.md`.
- Navigation and Dashboard correction (2026-11-09): replaced the single mixed sidebar with an Organization layout and a Workspace layout (workspace switcher in the sidebar, sidebar account area removed, header account control kept). Routes now `/workspaces/:id/{dashboard,repositories,pipelines,policies,members,roles,activity,settings}` with redirects for the old paths. The multi-workspace Overview was replaced by an Organization Overview (workspace list) and a per-workspace Dashboard with Chart and Table views; the service takes one `workspaceId` and verifies access itself. Tests: 54 node tests (24 shared, 30 mock-services) and 26 headless-Chrome tests (`pnpm --filter @qmentisai/tenant-web test:e2e`); lint and build pass.
- Mock data removed (2026-11-11): `packages/mock-services` and the browser e2e suite (which depended on seeded users) were deleted after a backup at `/home/narendra/qmentisai-sec-mock-backup` (outside the repository). Screens are kept. `apps/tenant-web/src/services/` now holds empty per-resource folders and `unconnectedService` placeholders that reject with `BACKEND_NOT_CONNECTED`; `backend/api` and `backend/workers` have empty module folders. Consequences: sign-in and all data screens show a "no backend" error until real clients exist; the shared authorization tests (24) remain. `pnpm build`, `pnpm lint`, `pnpm test` pass.
- Next action: Pipelines UI (only after Workspace and Repository sign-off). Root Console remains deferred.

## Update rules

- Update status only based on actual implementation evidence.
- Link relevant code changes or PRs when available.
- Record blockers and decisions.
- Do not mark a capability complete merely because its UI or placeholder API exists.
