# Reporting and Dashboards, Part E (cross-cutting checks, hardening, mutation sweep, docs): as built

**Built:** 2026-11-26 on main (after Parts A0, A, B, C, D and the AM amendment) in a worktree branch, not pushed. **Scope:** `SPEC.md` 16.2 (`RPT-S13`, `RPT-S14` and the sweeps), the three named fixes (rebuild coverage, file retention from the tick, the AM performance re-measure), the mutation sweep and the documents. Everything stays OFF behind `REPORTING_ENABLED=false`. `docs/api` was NOT regenerated (the lead does). No other part was changed beyond the files named in section 2.

## 1. Checks (12, line `E` of `expected.js`)

All are in `apps/api/test/security/helpers/reporting/reporting-e-checks.js`. The suite total is 1079 (baseline on main) plus 12 = **1091** (section 5).

| Id | What it proves | Class |
|---|---|---|
| `RPT-S13a` | Two tenants with the SAME workspace, repository and pipeline names and different counts (3 and 5 findings) are rolled up by the REAL rollup handler on the restricted role and read through a REAL second API process (`REPORTING_ENABLED=true`, the pattern of Part C): every rollup row belongs to the tenant's own pipelines and workspace and sums to its own count (all four daily tables, no row names the other tenant's pipelines), all 14 read DTOs answer 200 and carry none of the other tenant's ids or unique names, the shared and own names ARE present (not vacuous), the other tenant's session gets the identical 404 for every workspace read | database + HTTP |
| `RPT-S13b` | Each tenant generates a CSV and two PDFs through the real API (the worker handler in process) and the files are read back (PDF streams inflated, page strings decoded): ready, downloadable, own unique names present, none of the other tenant's ids, titles, paths or names, the CSV has exactly the tenant's rows, a report id of one tenant is the identical 404 for the other on read, download and delete (and the report survives), never in the other's list | database + HTTP |
| `RPT-S14a` | Flag-off sweep: the tick does not start (also for `"true"` as a string, a missing section, an empty config) and the worker entry starts nothing; the rollup handler refuses every mode (also a rebuild) without calling the repository (a tripwire) and writes nothing on the real database; the retention pass is a no-op; on the suite's own API EVERY operation the OpenAPI document lists under `/reporting` (derived from the document, and equal to the manifest) answers 401 without a session and the byte-identical 404 `RESOURCE_NOT_FOUND` with one; every `report_*` table and the reporting outbox queue are unchanged | database + HTTP |
| `RPT-S14b` | Route inventory sweep: the routes the REAL reporting router registers (module ON, on a recorder) equal an explicit manifest of 18 routes (method, path, tenant audience, permission and its catalog scope, rate limit, idempotency key on every POST, write limit on every write, nothing under `/platform`); nine planted deviations are each reported; the live OpenAPI operations equal the manifest; every manifest row answers 401 without a session, the identical 404 to another tenant's owner (workspace, report id or unknown id), 404 (workspace routes) or 403 (the tenant overview) to a member without any role, writes nothing on a denial, and works for the owner (control) | recorder (memory) + HTTP |
| `RPT-S10f` | Fix 1 (section 2.1): after a time-zone rebuild the state series of every day of the range is null (never a covered zero), the first exact day is gone until a live run of the new zone, the flow series is covered by the rebuild's own backfill runs, the old runs are voided (`failed`/`invalid_range`, never deleted), a later live run restores its own day only, a plain `clearRange` leaves the ledger alone | database |
| `RPT-S08h` | Fix 2 (section 2.2): the REAL tick expires and deletes an expired report file of a tenant that never exports again, leaves a live report, touches nothing while the module is off or the store root is unset, a failing store never stops it, 105 expired reports are all done by one pass (bounded loop) | database |
| `RPT-SM01` to `RPT-SM06` | The checks that kill the starred survivors of the mutation sweep (`MUTATION_BACKLOG.md` 4): CSV safety and assignee column gating, object key validation and store limits (real files), PDF text safety, failure codes and time-zone validation, the export gates (stubs), tenant-scope validation before any statement of every repository method, and the worker repository's object key and assignee privacy | memory (no database) |

The checks leave the shared suite world as they found it except for what they must add: the second world of `RPT-S13` and `RPT-S14b` (two tenants, a workspace each, findings, rollup rows, a handful of reports) and one role-less user.

**Overlapping ids are not constructible:** workspaces, repositories and pipelines have globally unique ids (`id` is the primary key), so two tenants cannot hold the same id. What overlaps in `RPT-S13` is names (workspace, repository, pipeline) and days; the rollup rows are keyed by `(tenant, pipeline, day, ...)` and no row of a tenant names the other's pipeline (asserted on the four tables).

## 2. The three fixes

### 2.1 Fix 1: a time-zone rebuild voids the run coverage (`packages/db/src/reporting/rollup/store.js`, `apps/workers/src/reporting/rollup/job.js`)

`AS_BUILT_AM.md` 6 recorded that a rebuild cleared the rollup rows but left the run ledger, so the days between the old first exact day and the restart read as covered zeros. `clearRange` now takes an optional `voidCoverage` flag (the 19-method frozen surface is unchanged; `RPTA0-16` stays green). With it, in the SAME transaction as the clear, every `succeeded` run that touches the range is set `failed` with `error_code = 'invalid_range'` (the role has UPDATE on the ledger and no DELETE; the CHECK of the table allows exactly that pair). The rebuild (`reason: timezone_changed`) passes the flag; nothing else does. Voiding is whole-run: a backfill batch that sticks out of the range loses its coverage outside it too (a gap is honest, a false zero is not). Effects, proved by `RPT-S10f`: `firstExactDay` becomes null, so every state series is null until the first live run of the new zone, the flow series is covered by the rebuild's own backfill runs, and the hourly tick re-queues yesterday's close (its close run is void). A succeeded close of the old zone is no longer shown in the run listing as succeeded; that is the intended meaning of "void". The Part A equivalence and DST checks (`RPT-S10a` to `RPT-S10e`) are unchanged and green.

### 2.2 Fix 2: file retention from the hourly tick (`apps/workers/src/reporting/rollup/tick.js`)

The tick now calls `expireReportFiles` (Part C) once an hour after queueing the rollups, through a new exported `runFileRetention`: only when `REPORTING_ENABLED` is exactly true, the export worker repository exists and `ARTIFACT_STORE_ROOT` is configured; at most 10 calls of 100 reports per tick; best effort (a failure is logged by code and never stops the tick). The tick had both dependencies already (`exportRepository` is in the worker deps, the store is built from `config.execution.artifactStoreRoot` as the export handler does). Before, files were removed only after another export job, so a tenant that never exported again kept its files for ever. Proved by `RPT-S08h` and `RPT-S14a`. A file that cannot be removed is still marked `expired` (existing behaviour of `expireReportFiles`: the download answers 410), and stays on disk until an operator removes it; nothing retries it.

### 2.3 Fix 3: performance re-measure at 100,000 findings

Helper: `apps/api/scripts/reporting-perf.js` (new, not run by CI): its own ephemeral PostgreSQL cluster, migrations, ONE tenant and ONE workspace with **100,000 findings** (70,000 open, all severities and types, SLA clocks set, a history row each), 20,000 approved reviews, 20,000 executions over 90 days, 3 repositories (one archived), 6 pipelines with a published configuration, `ANALYZE`; then the REAL read routes acting as `qm_reporting_ro` (the Part B fixture), cache OFF, sequential, 3 warm-ups and 30 timed samples (p95 is the 29th). PostgreSQL 18 on the development machine, fsync off.

| Endpoint | p50 ms | p95 ms | Target (SPEC 14) |
|---|---|---|---|
| posture (P-1 to P-10, AM) | 102 | **111** | under 300 live: met |
| coverage (S-4, AM) | 37 | **42** | none stated |
| sla (AM) | 167 | **186** | none stated |
| remediation 90 d (AM) | 259 | **342** | under 500: met |
| trends 90 d | 20 | 35 | under 200: met |
| aging | 159 | 179 | |
| scan-activity 90 d | 55 | 76 | |
| quality 90 d | 233 | 260 | |
| breakdown repository | 84 | 91 | under 200: met |
| top-risk | 67 | 86 | |
| workload | 76 | 81 | |
| overview 30 d | 141 | 167 | |

No target of SPEC 14 is missed, so **no index is proposed**. Caveats: this dataset differs from the one of `AS_BUILT_B.md` 8 (no rollup rows, no scan results or SBOM items, no status-history rows beyond creation), so the numbers are not a before-and-after comparison with Part B's (Part B's dataset made posture 215 and remediation 411 ms; this one is lighter on rows the AM statements join). The AM statements that changed (P-10 and the connection tile for posture, the coverage universe, the SLA targets view) are all inside the p95 above. One connection at a time, not a load test; the transactional ingestion benchmark with the reporting worker running (RPT-015) was not re-run.

## 3. Mutation sweep

`MUTATION_BACKLOG.md`: 380 mutants, 224 killed, 155 survived, 0 timeouts, 1 invalid (memory pass 342 mutants: 205 killed, 136 survived, 1 invalid; database pass 38: 19 killed, 19 survived). 43 survivors starred (tenant scope, permission gates, redaction, CSV and PDF safety, object key validation, limits); 34 were killed by `RPT-SM01` to `RPT-SM06`, 9 are residue judged equivalent. It is a SAMPLE (at most 20 per file in memory, 2 per file in the database pass); section 2 of the backlog lists what was not swept. The only change to the tooling is `MUTATION_GROUP=reporting` in `apps/api/scripts/mutation-worker.js`.

## 4. Files

- `apps/api/test/security/helpers/reporting/reporting-e-checks.js` (the 12 checks, the route manifest `REPORTING_ROUTE_MANIFEST` and `inventoryProblems`), `expected.js` (`E: 12`).
- Fixes: `packages/db/src/reporting/rollup/store.js` (+ the JSDoc line of `packages/db/src/reporting/index.js`), `apps/workers/src/reporting/rollup/job.js` (one call), `apps/workers/src/reporting/rollup/tick.js`.
- Tooling: `apps/api/scripts/reporting-perf.js` (new), `apps/api/scripts/mutation-worker.js` (the `reporting` group).
- Docs: this file, `MUTATION_BACKLOG.md`, `LIVE_TEST_PLAN.md`, one tracker row, one line of `docs/modules/README.md`.

## 5. Verification run

Run in the worktree on 2026-11-26 (ephemeral PostgreSQL 18, nothing pushed):

| Gate | Result |
|---|---|
| `pnpm test:security` | **1091 tests, 1091 pass, 0 fail** (baseline on main 1079 plus 12; about 11 minutes). A first full run had one failure, `RPT-S13a`, a defect of the check itself (it summed the rollup rows of the whole demo tenant, which other parts' data share, instead of the workspace of the check); fixed and re-run |
| `pnpm lint` | 0 errors; warnings unchanged (api 4, tenant-web 7, all pre-existing, none in a file of this part) |
| `pnpm build --force` | 2 tasks successful |
| `npx prettier --check apps packages` | all files formatted |
| `pnpm install --frozen-lockfile --offline` | up to date |
| `pnpm --filter @qmentisai/api contract:parity` | 0 contract differences (61 baseline, 150 Express operations); `docs/api` left untouched (git status clean after the run) |

## 6. Defects found elsewhere and patch proposals (nothing patched outside the three fixes)

- **D-E1 (low): the export handler has no `REPORTING_ENABLED` guard** (`apps/workers/src/reporting/export/index.js`, `createExportHandler`). The rollup handler returns without writing when the module is off; the export handler does not. In practice nothing reaches it (the worker entry starts nothing while the flag is off, and the routes cannot create a row), so `RPT-S14a` asserts what is true (the entry and the tick start nothing, the rollup handler refuses) and does not claim the export handler refuses. Proposed patch: in `createExportHandler`, `if (deps.config?.reporting && deps.config.reporting.enabled !== true) return async () => {}` before building the store (and a line in `RPT-S14a`).
- **D-E2 (informational): the reporting operations are listed in the OpenAPI document even while the module is off** (the operations exist and answer 404). This is by design (the document is static), recorded because `RPT-S14a` relies on it.
- **D-E3 (informational, tooling): copying a worktree with `cp -a` breaks the pnpm virtual store** (pnpm re-links and prunes it on the first `pnpm --filter` call), so the parallel in-place database sweep of the Findings part F cannot be run from copies in this environment; the database pass here ran sequentially in the worktree.

## 7. Not verified

Everything in `LIVE_TEST_PLAN.md` (gates R-1 to R-8): a real RabbitMQ round trip and scheduler tick; the provisioned `qm_reporting` and `qm_reporting_ro` logins over a password-authenticated connection (the suite proves the grants with `SET LOCAL ROLE`); a real Redis cache and the epoch bump from a real transition; the first-enablement backfill on the development database; a PDF read by a human; a human or screen-reader review of the charts; a tenant time-zone change on a real tenant. Also not verified: the 100,000-finding numbers under concurrent load and with the Part B dataset shape; the export of 50,000 rows under 60 seconds (Part C measured it); the mutation sweep is a sample and its survivors are not triaged beyond the starred ones.
