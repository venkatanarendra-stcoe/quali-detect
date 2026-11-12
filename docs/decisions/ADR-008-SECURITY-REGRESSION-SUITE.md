# ADR-008: Security regression suite (tenant isolation, authorization, session separation, segregation of duties)

- **Status:** Accepted (2026-11-11, on the product owner's instruction)
- **Date:** 2026-11-11
- **Amended:** 2026-11-11 (owner instruction): segregation of duties added to the allowed scope; scope and constraint wording restated below. The ADR keeps its number; no second ADR was created for the same decision.
- **Amended:** 2026-11-12 (`docs/modules/repositories-github/SPEC.md` §18.3, approved): the GitHub checks follow the workspace-level design (new area 11, `SCM-027..044`); the routing checks `SCM-022..026` and the tenant-level linking checks are re-pointed to the workspace endpoints; the data-access checks cover the new tables and functions (`DAL-127..146`). The suite is now 303 checks.
- **Decision owners:** Product owner (decision); Claude Code (implementation)
- **Relation to `CLAUDE.md`:** `CLAUDE.md` lists "test-case structures" as out of scope. This ADR makes **one narrow exception**: this suite, nothing else. Unit tests, UI tests, coverage targets and general API behavior tests remain out of scope.

## Context

`docs/STATUS_PHASE_1-4.md` found that the security-critical behavior (tenant isolation, the 404/403 rule, platform/tenant session separation) had been verified only by scratch scripts that lived outside the repository. Nobody else could re-run them, and a change to the request pipeline could silently regress them. ADR-007 (Fastify to Express 5) rewrites exactly that pipeline, so the checks must exist in the repository, must run against any HTTP transport, and must be proven to fail when the behavior breaks.

## Decision

Add a committed **security regression suite**, run with `pnpm test:security`.

**Allowed scope: ONLY the areas below (the fifth to the eleventh were added by the owner on 2026-11-11 and 2026-11-12), run by ONE command, `pnpm test:security`.** Feature tests, unit tests, UI/browser tests and test-case directory structures for anything else stay out of scope (see *Out of scope* and *Rules for contributors*).

**In scope (and only this):**

1. Tenant isolation: another tenant's resources by id (read, change, delete, assign, add as member), list leakage, tenant never taken from a header, query or body.
2. Authorization outcomes: a workspace the caller cannot see answers **404** with a body identical to a non-existent one; a visible resource without the permission answers **403**; escalation guard (SOD-3).
3. Platform/tenant session separation: tenant session on platform routes (404), platform session on tenant routes (401), no session (401), platform session before MFA (401 `mfa_required`, no data), cookie-name confusion, cross-audience sign-in, cross-site Origin (CSRF) refusal.
4. Segregation of duties: no self-escalation (SOD-3, check `AUTHZ-015`, part of the 68). SOD-1 (a reviewer cannot approve their own decision) and SOD-2 (a decision awaiting approval cannot be edited by its reviewer) get checks **in the same work item that builds the review/approval workflow**, because they cannot be exercised before it exists; adding them changes the count of checks and requires updating this ADR and the integrity test.

5. Sign-in and MFA throttling (added 2026-11-11 with ADR-010, owner instruction): progressive delay after the free attempts, identical behavior for existing and non-existing accounts (no enumeration), per-IP limit, refused attempts do not extend the wait, no hard lock. Checks `THR-001..009`.
6. Tenant restore window (added 2026-11-11, AUTHORIZATION Q25): who can restore a deactivated tenant and when, the tenant stays unusable while deactivated and after the window ends, `TENANT_DEACTIVATION_EXPIRED`. Checks `RST-001..006`. This is lifecycle/session separation behavior, kept to six checks.

7. Secret storage foundation (ADR-009): tenant isolation of secret references, AAD binding, no plaintext at rest, in views or in audit entries, message guard. Checks `SEC-001..009`. They run **in-process** against the disposable database (the runner passes `SECURITY_DATABASE_URL`) and import the secret store wiring, because the store has no HTTP surface yet; this is the one place the suite is not purely black box, and it ends when an HTTP surface exists.

8. HTTP edge (added 2026-11-11): audit-log tenant isolation on both read APIs (`AUD-001..007`), `Idempotency-Key` scoping by tenant and actor (`IDM-001..005`), entitlement denial and quota limits (`ENT-001..004`), CORS for unknown origins (`COR-001..003`) and the per-route rate limit (`RATE-001`). Twenty checks; the runner sets high global and write limits and a 200-request, 5-second auth window so the suite itself is never throttled.

9. GitHub integration and repositories (added 2026-11-11, `docs/modules/repositories-github/SPEC.md` §14.1; re-pointed 2026-11-12 to the workspace-level design of §18): webhook signature verification and fail-closed handling (`SCM-001`, `002`, `006`, `007`, `011`, `015`), tenant resolution only from the installation link (`SCM-003`, `004`, `021`), linking rules through the workspace endpoints (a second tenant claiming a linked installation is a generic `409`, organization role, personal account, listed installation, single-use state, only holders of `workspace_integration.manage` can start: `SCM-005`, `013`, `014`, `018`, `019`, `020`), repository isolation and the 404/403 rule (`SCM-008`, `009`, `010`), no token or key material in responses or audit entries (`SCM-012`), the reconciler and repository state transitions (`SCM-016`, `017`) and the workspace permissions (`SCM-022..026`: `workspace_integration.view`/`.manage` evaluated in the workspace of the URL, an unlinked connection cannot be used, a link id is bound to its workspace, tenant-level reads and the tenant setting need tenant keys, another tenant gets 404). The runner starts a **local GitHub stub** (`apps/api/test/security/helpers/github-stub.js`, plain HTTP, no network) and passes the API its address and test credentials; the suite stays black box over HTTP. The exceptions are the scheduled work of SCM-016 and SCM-017, which has no HTTP surface and runs the worker handlers **in-process** against the disposable database and the stub, like area 7, and the uninstall checks of area 11.

10. Data-access isolation (added 2026-11-11, owner instruction): every tenant-scoped repository function (all `apps/api/src/modules/*/repositories`, `packages/db` tenant repository, outbox, processed messages and secrets, and the SCM worker ownership verifier, state transitions, event consumer and sync job) is called **in-process** against the disposable database with the real row ids of tenant X and the id of another tenant Y as `tenantId`. It must return nothing, refuse (e.g. a composite foreign key), or create the row under the tenant it was given, and every row of tenant X must be unchanged afterwards. One check per function, `DAL-001..` (146 checks, including the authorization engine (`apps/api/src/authz/repository.js`) and entitlement/quota (`apps/api/src/entitlements/repository.js`) repositories, helper `apps/api/test/security/helpers/direct-repos.js`, table-driven). Reason: a layer above (workspace visibility, service checks) can hide the loss of a repository tenant filter, so the HTTP checks alone do not protect each filter. This is a second in-process exception next to areas 7 and 9; functions that are not tenant-scoped by design (platform installations, platform identity, user-level lookups, platform audit, advisory locks) are not checked and are listed in the work report. Mutation-tested: removing the tenant condition of any scoped function makes at least one check fail (see Validation).

11. GitHub workspace-level integration (added 2026-11-12, SPEC §18.3 and §18.6, owner instruction). Source-control linking belongs to the workspace: `SCM-027..044`. They run against the local GitHub stub and the real HTTP API, with controls inside each check (the legitimate request is proved to work) so no denial is vacuous.
   - Who may link: a workspace-scoped Manager without tenant Admin completes the whole D4/D5 flow and gets 404 for a workspace they cannot see (`SCM-027`); Viewer, Developer, Lead, Dev Lead and Security Analyst get 403 on start and authorize (`SCM-028`).
   - Second workspace on the same installation: 201 without a 409 and one tenant installation record (`SCM-029`); the GitHub-side ownership checks run again for that person, so an organization member is refused (`SCM-030`).
   - Linking state: bound to the workspace, user and session, refuses a workspace named in the request, and links only the workspace it was minted for (`SCM-031`); consuming it re-checks `workspace_integration.manage` in the state's workspace, so a person who lost the key after minting gets 403 (`SCM-032`); an expired state is refused (`SCM-033`; the runner sets `SCM_LINK_STATE_TTL_SECONDS=3`).
   - Tenant setting "allow workspace admins to link source control": default on, only `integration.manage` changes it (`SCM-034`); off means start, authorize and consume answer 403 `workspace_linking_disabled` while test connection, allow-list edits and unlink keep working, and both changes are audited (`SCM-035`).
   - Workspace isolation under one installation: workspace A cannot list, connect or see workspace B's repositories, allow-list or link records (404 for a workspace the caller cannot see, also through A's URL with B's link id: `SCM-036`; 403 where visible without the key: `SCM-037`).
   - Allow-list: a repository not on the list cannot be connected, is not offered, only `.manage` edits it, a connected one cannot be removed (`SCM-038`); a repository on one workspace's list cannot be added to another's, generic 409 that names no workspace (`SCM-039`).
   - Unlink disconnects only that workspace's repositories, keeps the installation record, needs the typed account name, and linking again restores them (`SCM-040`).
   - Tenant read-only view: `integration.view` lists installations with workspace names only for workspaces the caller can see, others 403 (`SCM-041`); the removed tenant-level and routing endpoints answer 404 (`SCM-042`).
   - Uninstall (`installation.deleted` through the signed webhook, then the scm event consumer in-process): all workspaces' repositories disconnected with `installation_revoked`, one audit entry per workspace plus one tenant-level entry, one notification message, later events and webhooks change nothing (`SCM-043`); the notification handler resolves the active holders of tenant `integration.manage` and of each workspace's `workspace_integration.manage`, once each, never a Viewer or anyone of another tenant (`SCM-044`).
   The two in-process parts (the event consumer and the notification handler) have no HTTP surface yet, like areas 7 and 9.

Also covered, as part of areas 1 to 3: tenant suspension takes effect immediately and does not affect another tenant (`SUSP-001..003`, part of the 68).

**Out of scope:** feature tests, unit tests, frontend/browser tests, load or performance tests, coverage thresholds, functional tests of other behavior, RabbitMQ and workers, CI configuration (no CI is in scope for the project).

## Design

- **Black box over HTTP.** The suite talks to a running API with `fetch`; it imports no API code. The same checks therefore run unchanged against Fastify now and Express after ADR-007.
- **Runner** (`apps/api/scripts/security-suite.js`): provisions a **disposable PostgreSQL** (an ephemeral local cluster built with `initdb`/`pg_ctl` from `PG_BIN_DIR`, `/usr/lib/postgresql/*` or `PATH`, in a temporary directory on a free port; no Docker), applies migrations and the seed, starts the API as a child process with a clean environment, runs the tests, and always tears everything down. Alternatively `SECURITY_TEST_DATABASE_URL` selects an existing database, **refused unless its name contains "test"**; its URL is never printed. The runner starts the API with a short throttle curve (3 free failures, waits of 1 s, 2 s, 4 s cap) so the THR checks finish in seconds; production defaults are in ADR-010; the restore window is set to 4 s (`TENANT_DEACTIVATION_RETENTION_SECONDS`) for the `RST` checks. Exit codes of the runner: 0 passed, 1 a check failed, 2 the environment is unusable (with an explanation); pnpm reports 1 for any non-zero exit, so the message distinguishes them.
- **Secrets are random per run** (mock passwords, MFA code); none is stored in the repository.
- **World built through the public API only:** tenant A is the seeded demo tenant; tenant B is created through `POST /platform/tenants`, its administrator is invited and accepts, then creates a workspace, group, custom role and workspace role assignment. Everything created carries a random suffix, so the suite can be re-run on the same disposable database.
- **Framework:** `node:test` (built into Node 22). **No new dependency.**
- **303 checks**: the original 68 (`ISO-001..037`, `AUTHZ-001..015`, `SESS-001..013`, `SUSP-001..003`), taken from the audit, plus 9 added with ADR-010 (`THR-001..009`) 6 for the tenant restore window (`RST-001..006`), 9 for the secret storage foundation (`SEC-001..009`) 20 for the HTTP edge (`AUD`, `IDM`, `ENT`, `COR`, `RATE`) 44 for GitHub integration and repositories (`SCM-001..044`) and 146 for data-access isolation (`DAL-001..146`). An **integrity test** fails if the number of checks or their ids/names change, so a check cannot be dropped silently; changing the count requires updating this ADR.
- **Controls** (17, not counted in the 302; the 17th proves that wrong passwords below the free attempts do not block a legitimate sign-in) assert that the legitimate version of each request *succeeds* (an owner reads their own workspace, user, group, role and assignments; the platform session works after MFA). Without them, a transport that stopped mounting routes would answer 404/401 everywhere and every denial check would pass vacuously.
- Error responses are also checked for the error envelope and `meta.correlationId`, and the cross-tenant checks assert that the response body contains no identifier of the other tenant.

## Validation that the suite can fail (performed 2026-11-11 in a separate git worktree, main tree untouched)

| Deliberate bug | Result |
|---|---|
| Hidden workspaces answer 403 instead of 404 | 6 checks fail (`AUTHZ-001..005`, `AUTHZ-007`) |
| User lookup by id only (no `tenantId`) | 5 checks fail (`ISO-007..010`, `ISO-035`), including the PATCH-suspend one |
| Origin/CSRF check removed | `SESS-013` fails |
| Platform MFA no longer required | `SESS-009` fails |
| Workspace loader without the tenant filter | not caught by the HTTP checks (the visibility check answers 404 independently); **caught since area 10** by the `DAL` check of `workspaces.findById` |
| 2026-11-12 sweep (scratch copies): `tenantId` removed from each new or changed workspace-link, allow-list, tenant-setting and repository function (`apps/api/src/modules/integrations`, `repositories`), the scm worker fan-out and the notification recipient lookup | each function is caught by at least one `DAL-127..146` or existing `DAL` check, or by `SCM-034..044`; the worker fan-out bodies `revokeInstallation`/`suspendInstallation` are equivalent mutants (the workspace-link id filter already scopes them; the shared `changeInstallation` and `disconnect` are caught by `DAL-141/142`) |

## Rules for contributors

- A new tenant-owned route family needs checks in this suite in the same work item: cross-tenant access by id (404), hidden-workspace behavior where it applies (404 vs 403), and a control that the legitimate request works.
- Change to authentication, sessions, tenant context, authorization or the Express/Fastify pipeline: `pnpm test:security` must pass before commit.
- Never point the suite at a real database; never weaken a check to make it pass.

## Alternatives considered

1. Keep scratch scripts outside the repo: not reproducible, not reviewable.
2. A full test framework with unit tests: broader than the owner approved and in conflict with the project constraints.
3. In-process `app.inject` tests: faster but Fastify-specific, so unusable as the gate for ADR-007.

## Consequences

### Positive
- The security-critical behavior is protected by a repeatable, transport-independent gate that runs in about 7 seconds.
- It is the acceptance gate for ADR-007.

### Negative / trade-offs
- Needs PostgreSQL server binaries on the machine (or a disposable database URL); no Docker.
- Depends on the seeded demo data (`demo.*@demo.example`); a change to the seed must keep the suite working.
- Covers only the scope above; it is not a general test suite.

## Security and operational impact

- Runs only against a disposable database it creates, or an explicit one whose name contains "test"; uses random credentials; leaves no files outside a temporary directory it deletes.
- Audit-log immutability means rows created by a run in an external test database stay there (use a throw-away database).

## Related documents

- `docs/STATUS_PHASE_1-4.md` (the source of the 68 checks)
- `docs/decisions/ADR-003-TENANT-ISOLATION.md`, `docs/AUTHORIZATION.md` §5.9 (404 vs 403), `docs/architecture/TENANT_ISOLATION.md`
- `docs/decisions/ADR-007-REPLACE-FASTIFY-WITH-EXPRESS-5.md`
- `apps/api/test/security/README.md`
