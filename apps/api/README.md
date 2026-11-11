# @qmentisai/api

Fastify API for QmentisAI: a modular monolith (ADR-002) under `/api/v1`. Specs: `docs/architecture/BACKEND_ARCHITECTURE.md`, `docs/technical/API_STANDARDS.md`.

```bash
pnpm --filter @qmentisai/api dev      # node --watch, loads apps/api/.env if present
pnpm --filter @qmentisai/api start
```

## What exists (Phase 2, part 1)

- `src/app.js` `buildApp({ config })`: per-call Fastify instance, no global mutable state. Plugin order: correlation, envelope, error handler, readiness, OpenAPI, modules.
- `src/config`: environment validated with Zod; invalid env fails startup (messages list variable names, never values).
- Logging: Pino via Fastify. `correlationId` per request from a safe `x-correlation-id` or a new UUID, echoed in the response header; auth headers, cookies and secret-like keys are redacted; request logs carry method and path only.
- Errors: `AppError` subclasses with stable codes from `@qmentisai/contracts`. One handler returns the envelope `{ success: false, error: { code, message, details? }, meta: { correlationId } }`; unknown errors become `INTERNAL_ERROR` and are logged server-side only.
- Success envelope via `reply.success(data)` and `reply.paginated(items, pagination)`.
- OpenAPI generated from route Zod schemas, served at `/api/v1/openapi.json` (`OPENAPI_ENABLED`).
- `/health` (liveness) and `/ready` (runs checks registered with `app.readiness.register(name, fn)`) are unversioned probes.
- `src/lib/validation.js`: Zod validator for route `params | querystring | body | headers`, plus `parseWith` for services and message handlers.
- `src/lib/query.js`: `createCollectionQuerySchema` (page, pageSize, allow-listed `sort=field:asc,...`, declared filters, unknown params rejected), `buildPaginationMeta`, in-memory `sortItems`/`paginateItems`, and Prisma `toPrismaPaging`/`toPrismaOrderBy`.

## Module pattern

`src/modules/system` is the reference module. Layout: `routes/ controllers/ services/ repositories/ schemas/ policies/ events/ listeners/ mappers/ constants/ index.js`. The module plugin builds repository -> service -> controller from app decorators, and exports a descriptor that `src/modules/index.js` registers. Routes stay thin, repositories own data access (tenant-scoped), controllers call policies before services.

## Identity, authorization and access management

- `src/auth`: mock provider, cookie sessions (only token hashes stored), tenant/platform contexts. `src/plugins/authentication.js` requires every route to declare `config.audience` (`public | user | tenant | platform`).
- `src/plugins/authorization.js`: `app.authz.authorize(permissionKey, scopeResolver)` preHandler on top of the pure engine in `@qmentisai/shared` (`resolveEffectivePermissions`, `can`). Scope resolvers: `app.authz.scopes.tenant`, `app.authz.scopes.workspace(param)`. Unseen resources answer 404, visible-but-forbidden 403.
- `src/audit` (`app.audit`): strict, transactional, immutable audit writes (DB triggers block UPDATE/DELETE/TRUNCATE).
- `src/entitlements` (`app.entitlements`): `checkEntitlement`, `assertWithinLimit`, `consumeQuota`, `releaseQuota`.
- Modules: `identity`, `platform-identity`, `users`, `groups`, `roles`, `role-assignments`, `workspaces`, `workspace-members` (spec: `docs/modules/access-management/SPEC.md`).

Platform tenant management (`platform-tenants`): list, provision, detail, suspend/reactivate/deactivate (metadata and counts only, audited).

Platform sign-in requires MFA (`POST /api/v1/platform/auth/mfa/verify`, mock code `MOCK_PLATFORM_MFA_CODE`); see `docs/AUTHORIZATION.md` §16.

Not implemented yet: RabbitMQ publishing from modules (no outbox), permission caching, SSO/MFA.
