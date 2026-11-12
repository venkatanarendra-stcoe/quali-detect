# Security regression suite

Run: `pnpm test:security` (from the repo root). Decision and scope: `docs/decisions/ADR-008-SECURITY-REGRESSION-SUITE.md`.

It covers **only** tenant isolation, the 404/403 authorization rule, platform/tenant session separation, segregation of duties and the sign-in/MFA throttling of ADR-010: 302 checks, 17 controls and 1 integrity test. It is a black box over HTTP, so it works against any implementation of the API (Fastify today, Express after ADR-007).

## What it needs

- PostgreSQL server binaries (`initdb`, `pg_ctl`): found through `PG_BIN_DIR`, `/usr/lib/postgresql/*/bin` or `PATH`. The runner starts an **ephemeral** cluster on a free port in a temporary directory and deletes it afterwards. No Docker.
- or `SECURITY_TEST_DATABASE_URL`: an existing, empty, **disposable** database. The runner refuses a database whose name does not contain "test" and never prints the URL.
- Nothing else: no Redis, no RabbitMQ, no `.env` files. Passwords and the MFA code are random for each run.

Exit codes of the runner (`node apps/api/scripts/security-suite.js`): `0` passed, `1` a check failed (the last API log lines are printed), `2` the environment is unusable (the message says why). Through `pnpm test:security`, pnpm reports `1` for any non-zero exit, so read the message to tell the two apart.

## Files

- `../../scripts/security-suite.js`: provisions the database, migrates and seeds, starts the API, runs the tests, tears everything down.
- `security.test.js`: the checks (data-driven, grouped) plus controls and the integrity test. The SCM groups run partly in-process: the scm worker's handlers (reconciler, state transitions, event consumer for `installation.deleted`) and the notification handler, against the disposable database and the stub.
- `helpers/http.js`: minimal `fetch` client with manual cookie handling.
- `helpers/world.js`: builds tenant B and all sessions through the public API.
- `helpers/github-stub.js`: the local GitHub stand-in (plain HTTP, no network) the SCM checks link against; the runner also sets `SCM_LINK_STATE_TTL_SECONDS=3` so `SCM-033` can prove that an expired linking state is refused.
- `helpers/direct-repos.js`: data-access isolation (`DAL-*`): builds three tenants directly in the database (X owns the data, Y is the "wrong" tenant, Z holds the uninstall fan-out and notification fixtures) and calls every tenant-scoped repository function in process with another tenant's id (table-driven, one check per function; includes the workspace-link, allow-list and tenant-setting functions, the uninstall/suspension fan-out of the scm worker and the notification recipient lookup).

## Rules

- A new tenant-owned route family adds checks here in the same work item (cross-tenant 404, hidden-workspace 404 vs 403 where relevant, and a control that the legitimate request works).
- The number of checks is asserted (302: the original 68, 9 `THR` throttling checks of ADR-010, 6 `RST` tenant-restore checks, 9 `SEC` secret-storage checks of ADR-009, 20 HTTP-edge checks `AUD`, `IDM`, `ENT`, `COR`, `RATE`, 44 `SCM` checks for the workspace-level GitHub integration and repositories (SPEC §18.3: linking permissions, second workspace, state binding and expiry, tenant setting, workspace isolation, allow-list, unlink, uninstall fan-out and notification), run against a local GitHub stub, and 146 `DAL` data-access isolation checks). Changing it means updating ADR-008.
- Never weaken a check to make it pass; never point the suite at a real database.
