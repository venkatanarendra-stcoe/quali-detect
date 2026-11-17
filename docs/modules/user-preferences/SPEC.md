# User preferences — Module Specification

**Status:** Implemented (2026-11-13)
**Owner:** Platform (owner decision of 2026-11-13: a proper module, not browser storage)
**Last updated:** 2026-11-17 (default workspace and landing withdrawn, owner decision, Confirmed)
**Related ADRs:** ADR-003 (tenant isolation), ADR-007 (Express 5, route kit), ADR-008 (security suite)

Labels follow `docs/README.md`: everything below is **Confirmed** (the owner's decision and instructions of 2026-11-13) unless a line says **Recommended** or **Open**.

> **Withdrawn 2026-11-17 (owner decision, Confirmed):** the briefly specified default-workspace preference (`defaultWorkspaceId`, requirements UP-006..008, the `default_workspace_id` column, `GET /me/landing`, checks `PREF-014..018`, `LAND-001..008`, `DAL-292`) was removed. The module is back to the single accent preference. Post-login landing is a client-side rule on permissions (docs/AUTHORIZATION.md decision 31). Migration `20261117120000_drop_user_preferences_default_workspace` drops the column; the earlier migration stays in history. UP-006..008 are intentionally unused.

## 1. Purpose

Store small, per-user interface preferences on the server so they follow the user across browsers and devices. Version 1 has one preference: the **accent colour**. The module is deliberately tiny and extensible.

## 2. Scope

### In scope
- `GET /api/v1/me/preferences` and `PUT /api/v1/me/preferences` for the signed-in user in the active tenant.
- The accent palette keys and the default in `@qmentisai/shared` (`ACCENT_KEYS`, `accentKeySchema`, `DEFAULT_ACCENT`).
- Table `user_preferences`, repository, DTO mapper, OpenAPI, security checks `PREF-001..013`, `DAL-222..223`.

### Out of scope
- The colour values per accent key (light and dark): defined by the UI package (`packages/ui`), not here.
- Frontend wiring (applying the accent, a settings screen).
- Platform (Root Console) preferences: a separate audience and a separate store if ever needed.
- Organization-wide defaults or admin-set preferences (no such requirement).

## 3. Actors and permissions

| Actor / role | Action | Scope | Permission |
|---|---|---|---|
| Any authenticated tenant user (any role, any membership of the active tenant) | Read and write **their own** preferences | Own user in the session's tenant | None. Authentication and an active, usable tenant are the only gates. |
| Platform (Root Console) session | None | — | Cannot reach the route (401, see §8). |

Nobody can read or write another user's preferences: the API has no input that names a user or a tenant.

## 4. Functional requirements

| ID | Requirement | Priority | Status |
|---|---|---|---|
| UP-001 | `GET /me/preferences` returns every preference with its value; the default when nothing was saved. Reading never creates a row. | Must | Implemented |
| UP-002 | `PUT /me/preferences` upserts the supplied preferences; unsupplied preferences keep their value. Idempotent. | Must | Implemented |
| UP-003 | `accent` must be one of `ACCENT_KEYS`; anything else is 400. | Must | Implemented |
| UP-004 | The body is strict: an unknown field (including `userId`, `tenantId`) is 400; an empty body is 400. A query string with any parameter is 400. | Must | Implemented |
| UP-005 | User and tenant come only from the authenticated session. | Must | Implemented |

## 5. Business rules

1. Palette (**Confirmed**): `mint` (default), `violet`, `blue`, `cyan`, `teal`, `emerald`, `amber`, `orange`, `rose`. No indigo, no black or white, no severity or status colour (so an accent is never read as a finding severity or a status).
2. Preferences are per user **per tenant**: a user who belongs to two tenants has two independent rows.
3. A missing row, a null column or a stored value that is no longer in the palette reads as the default; the default can change later and applies to everyone who never chose.
4. There is no "delete preferences" operation; choose `mint` to return to the default look.

## 6. Workflows

Read: authenticate -> tenant context from the session -> `find(tenantId, userId)` -> DTO (defaults filled in).
Write: authenticate -> tenant context -> rate limit (write profile) -> validate (strict body, empty query) -> `upsert(tenantId, userId, supplied fields)` -> DTO. Failure paths: 401 no/invalid session or platform session; 403 `TENANT_SUSPENDED` / `TENANT_CONTEXT_REQUIRED` (no active tenant); 400 invalid input; 429 rate limit; 404 only if the membership vanished between authentication and the write (the composite key refuses the row).

Suspended tenants (the existing convention): every tenant-audience route, read or write, answers 403 `TENANT_SUSPENDED`; this module adds no exception.

## 7. Data model

Table `user_preferences` (migration `20261113220000_user_preferences`), model `UserPreference`:

| Column | Type | Notes |
|---|---|---|
| `id` | uuid PK | |
| `tenant_id` | uuid, not null | |
| `user_id` | uuid, not null | |
| `accent` | text, null | null = default applies. Key from `ACCENT_KEYS`; validated by the API, not by a DB CHECK (see below). |
| `created_at`, `updated_at` | timestamptz | |

- Unique `(tenant_id, user_id)`: one row per membership; the repository addresses the row only through this key.
- Composite foreign key `(tenant_id, user_id)` -> `tenant_memberships(tenant_id, user_id)`, `ON DELETE CASCADE`: the row can only belong to a user of that same tenant (the same pattern as `group_members`); removing the membership removes the preferences. A tenant cannot be deleted while memberships exist (RESTRICT on the tenant), so no separate tenant key is needed.
- No RLS: the codebase enforces isolation in the repositories plus composite keys (ADR-003); there is no row-level security anywhere.
- Retention: with the membership.

**Columns, not jsonb (decision, justified).** Typed nullable columns give atomic partial updates (`upsert` writes only the supplied columns, so two requests changing different preferences cannot overwrite each other), real column types, and no unbounded user-controlled blob. jsonb would save a migration per new preference but needs merge logic or read-modify-write, and lets unvalidated keys accumulate. Each new preference is one small, reviewed migration plus an entry in the Zod schema. **Recommended** to revisit only if preferences become numerous or user-defined. The palette is not a DB CHECK/enum on purpose: changing the palette must not need a migration; the Zod enum is the single source and an out-of-palette stored value reads as the default.

## 8. API contract

Both: audience **tenant** (session cookie; tenant from the session only), no permission, no path parameter, query string must be empty.

`GET /api/v1/me/preferences` -> 200 `{ success: true, data: { accent }, meta: { correlationId } }`.

`PUT /api/v1/me/preferences` (rate limit: `write` profile) — body `{ "accent": "<key>" }`, strict, at least one field -> 200 with the same DTO as GET (the stored values). Idempotent by nature (the same body gives the same state and answer), so no `Idempotency-Key`.

Errors (standard envelope): 400 `VALIDATION_FAILED` (unknown field, empty body, accent outside the palette, any query parameter), 401 `UNAUTHENTICATED` (no session, or a platform session: the tenant and platform routers are separate), 403 `TENANT_SUSPENDED` / `TENANT_CONTEXT_REQUIRED`, 404 `RESOURCE_NOT_FOUND` (membership vanished), 429 `RATE_LIMITED`.

## 9. Events and asynchronous work

None. A cosmetic preference emits no event and no outbox row.

## 10. Frontend requirements

Out of scope for this module; the UI agent applies `accent` (colour values from `packages/ui`) and may offer a picker in the user's account settings. Loading, error and unauthorized states follow the usual data-view rules. Suggested: read once after sign-in, write on change with an optimistic update.

**As built (2026-11-13):** the palette values live in `packages/ui/src/accents.css` (`html[data-accent]`, mint = no override, Root Console ignores it) with measured contrast in `docs/design/DESIGN_SYSTEM.md` §2.5; `AccentProvider` and the picker are in `apps/tenant-web/src/features/account` (route `/account`, Preferences tab; no navigation entry yet because `@qmentisai/shared` navigation has none). The derived colour values are **Confirmed (owner, visual sign-off 2026-11-16)**.

## 11. Security and privacy

- Isolation: user id and tenant id come from `request.principal` (`actorFrom`), never from input; there is no id to forge. Forged body fields and query parameters are rejected (400) rather than ignored, and `x-tenant-id` is ignored as everywhere else.
- Repository: Prisma only inside the repository; every query carries `tenantId` and `userId` through the compound unique key; never by user id alone (`DAL-222..223`).
- DTO mapper: the row (ids, timestamps) is never returned.
- **Audit: not required** (cosmetic, per-user, non-sensitive, no effect on anyone else). No audit entry is written; the write is rate limited like other writes. **Recommended** to keep it that way; preferences that affect security or other people would need audit.
- Personal data: none beyond the choice itself.

## 12. Observability

Standard request logs with correlation id, `tenantId` and `userId` bound by the middleware. No metrics beyond the HTTP ones.

## 13. Dependencies

`tenant_memberships` (composite key), route kit, authentication and tenant-context middleware, `@qmentisai/shared` (palette), `@qmentisai/contracts` (envelope schemas).

## 14. Acceptance criteria

- [x] Palette keys, `DEFAULT_ACCENT = "mint"` and a Zod enum in `@qmentisai/shared`.
- [x] Migration and model with the composite tenant-safe key and unique `(tenant_id, user_id)`.
- [x] `GET`/`PUT /me/preferences` as above, in OpenAPI; `pnpm contract:snapshot` diff is exactly the two operations (accepted in `parity-accepted.json`).
- [x] Security checks: `PREF-001` no session, `PREF-002` no session PUT writes nothing, `PREF-003` platform session, `PREF-004` defaults and no row on read, `PREF-005` saved under own tenant/user, `PREF-006` idempotent, `PREF-007` out-of-palette accents, `PREF-008` all palette keys, `PREF-009` forged body fields, `PREF-010` forged query/header, `PREF-011` two users of one tenant, `PREF-012` two tenants, `PREF-013` suspended tenant; `DAL-222` find and `DAL-223` upsert with another tenant's id; one control (a viewer, no special permission, reads and writes).
- [x] `pnpm test:security`, lint, build, parity pass (see PROGRESS_TRACKER).

## 15. Open questions

- None blocking. **Open (not decided):** whether a future "reset to defaults" is wanted (today: choose `mint`).

## 16. Implementation notes

- Module `apps/api/src/modules/user-preferences` (route kit layout; no events, listeners or policies: nothing to emit or authorize).
- The platform session answers **401** (not 404) on tenant routes, like every tenant route (`SESS-004..006`); only tenant sessions on platform routes get 404.
- `PUT` replies 404 if the membership disappeared mid-request (`P2003` on the composite key) instead of a 500.
- Mutation results of the new checks are recorded in `docs/development/PROGRESS_TRACKER.md`.
