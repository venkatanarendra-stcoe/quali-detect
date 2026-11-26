# Reporting and Dashboards, Part A (the rollup core): as built

**Built:** 2026-11-26 on `16486ff` (Part A0), in a worktree branch, not pushed. **Scope:** `SPEC.md` 18 row A, 7.2, 8, 10 and the owner rulings of 2026-11-26 (`SPEC.md` 0.1), against the frozen surface of `AS_BUILT_A0.md`. Nothing here edits a file of Part A0: the 19 repository methods and the two worker factories are filled in Part A's own directories. Everything stays OFF behind `REPORTING_ENABLED=false`. **Not verified here:** a running reporting worker against RabbitMQ (the consumer, the outbox relay, real redelivery), a production role provisioning, any HTTP route, any export, a tenant with a real GitHub history, the dev database (nothing in this work touched it).

## 1. The severity series is FORWARD-ONLY (the owner's gate, `SPEC.md` 0.1 and 17.1 D-1)

The ruling: backfill the per-severity series only if the equivalence test proves an exact reconstruction, otherwise forward-only. **The reconstruction is not exact, so the series is forward-only.** This is the true outcome of `RPT-S10b`, not a weakened test:

- **What is exact at any past instant `T`:** the status of every finding (the latest `report_status_events_v` row with `created_at <= T`), hence the totals that do not depend on severity (open, backlog, work in progress, awaiting verification per pipeline and scan type). `RPT-S10b` proves it against the in-memory ground truth of a dataset at four past instants.
- **What is not:** the split by severity. The effective severity changes (a) through an approved review override (`report_decisions_v` shows only the NEW value and when; the value before it is not in any view, because `report_findings_v` carries only the current severity and not `tool_severity` or `severity_override`) and (b) through a **tool re-rate on recurrence** (Findings `EX-5`, ingestion `UPDATE`s `tool_severity` and `severity` with no history row, no decision and no audit row). A finding is therefore counted under its CURRENT severity at a past `T`; for (a) the row is flagged `severityExact = false`; for (b) nothing marks it, so **no flag can certify a past day**. `RPT-S10b` demonstrates both on the dataset (a mismatch with `severityExact` false after an override, and a mismatch with `severityExact` true after a re-rate).
- **At `T = now` it is exact** (`RPT-S10a`: equal, key by key and counter by counter, to the ground truth AND to an independent computation over `report_findings_v` with the shared SLA function, on a dataset with overrides, a re-rate, reopenings, accepted risk (one expired by time), suppression, fixed and verified findings, false positives, two workspaces and two tenants).

What the code does about it:

| Series | Written by | Backfill |
|---|---|---|
| State counters (open, backlog, work in progress, awaiting verification, SLA on track, due soon, breached, exceptions in force, open age sum), per severity | **a live run only**: the hourly incremental (today, `T = now`) and the day close **while it is still exact** (within `closeStateMaxLagMs`, default 6 h, of the day end, and no approved severity override decided after `T`; otherwise the last hourly snapshot of that day stays) | **never** (it neither writes nor zeroes a state column) |
| Flow counters (`new`, `fixed`, `closed_other`, `reopened`) | incremental (yesterday and today), close, backfill | yes. A flow count is attributed to the finding's CURRENT severity (the history row has none): the per-day total is exact, the split by severity is not. No chart in the SPEC needs the split (T-1, T-4, R-2, R-8 sum over severity) |
| Executions, decisions | incremental, close, backfill | yes (decisions at DECISION time) |
| SBOM components | incremental, close, backfill | **only the pipeline's latest result** (the view `report_sbom_latest_v` keeps one result per pipeline): the series is complete from the first live run |

The migration has no `severity_exact` column, so no day carries a flag. **The first exact day is recorded in `report_rollup_runs`: it is `min(day)` over the succeeded runs of mode `incremental` or `close`** (a backfill run never counts). Consequences for Part B and the UI, to be read with this table: T-2 (open per severity), T-3 (burn-down), T-5 (awaiting verification over time) and the point-in-time posture have NO data before that day (the API must not draw a past zero as data: "rollup starts on D"); T-1, T-4, R-2, R-8, S-1, S-2, S-6, S-7 and the decision series are backfilled from the earliest history row, capped at the 25-month retention.

**A time-zone change rebuild clears the range** (`qm_reporting_clear_range`), which also removes the state snapshots of those days (they were keyed by the old zone's days and cannot be rebuilt); the state series restarts at the next live run. The SBOM rows of the cleared range are likewise not recoverable beyond each pipeline's latest result. A rebuild therefore equals a fresh build in the new zone by construction (`RPT-S10e`), and the UI should say so ("Recomputing; severity history restarts today").

A decision for the lead if the owner wants the severity trend backfilled after all: it needs `tool_severity`, `severity_override` and a severity-change record in the sources (a `finding_severity_history` table written by `transitionFinding` and by ingestion's re-rate), which is a Findings change, not a reporting one.

## 2. Files

| Directory | File | Content |
|---|---|---|
| `packages/db/src/reporting/rollup/` | `index.js` | `buildRollupMethods`: the 19 frozen methods (no addition, no rename) |
| | `state.js` | `computeFindingsStateAsOf`: THE one "state as of `T`" function (SQL over the views, grouped per workspace, repository, pipeline, scan type, severity) |
| | `flow.js` | `computeFindingsFlow`, `computeExecutionsDays`, `computeDecisionsDays`, `computeSbomDays` (tenant-local day buckets from the shared period helpers, applied with `width_bucket` over epoch thresholds, so a 23 or 25 hour day is exact and the database never decides what a local day is) |
| | `store.js` | the four idempotent upserts, `clearRange`, `purgeExpired` |
| | `runs.js` | `getTenantSettings`, `listActiveTenants`, `listPipelineChains`, `earliestHistoryAt`, `startRun`, `finishRun`, `findLatestRun`, `listRuns` |
| | `util.js` | statement timeout, input errors, day thresholds, UUID check |
| `apps/workers/src/reporting/rollup/` | `index.js` | the two frozen factories delegate here |
| | `handler.js` | the `reporting.rollup.requested` handler |
| | `job.js` | incremental, close, backfill, rebuild; error classification |
| | `tick.js` | the hourly tick, first-enablement backfill, retention purge |
| `packages/db/scripts/` | `reporting-backfill.js` | operator command that QUEUES a backfill of one tenant (outbox) |
| `apps/api/test/security/helpers/reporting/` | `reporting-a-checks.js`, `reporting-a-dataset.js`, line `A` of `expected.js` | the suite part and its dataset (ground truth in memory; a SQL generator of 100,000 findings) |

## 3. Behaviour

- **State as of `T`** (`state.js`): status at `T` = the latest history row (`ORDER BY rev DESC`) with `created_at <= T` (a finding with no row at `T` does not exist at `T`). Open, backlog, work in progress and awaiting verification come from the shared lifecycle constants (`OPEN_FINDING_STATUSES`, `BACKLOG_STATUSES`, `WORK_IN_PROGRESS_STATUSES`; awaiting verification is inside work in progress, so the table CHECKs hold). SLA: an open finding not in an SLA-stopped status with a stored `sla_due_at`: `breached` when `T` is after the due date, `due_soon` when the time left is at most `SLA_DUE_SOON_FRACTION` of `due - sla_started_at`, otherwise `on_track`. **Approximation, stated:** the due date and the clock start are the STORED (current) ones, not recomputed from the SLA targets (the views do not carry the tenant's SLA targets or the severity at `T`), so SLA counts of a past `T` follow the current clock; at `T = now` they are exact. Exceptions in force: status at `T` is `accepted_risk` or `suppressed` and an exception decided at or before `T` is neither ended nor expired at `T` (the exception half of `report_decisions_v`). Age: whole seconds from `first_detected_at` to `T` summed over open findings.
- **Rows carry** `severityExact` (not stored; the incremental run writes at `now` and the close checks it), and the returned array carries `asOfHistoryId` (not enumerable), the newest history row read, which the run row stores as `as_of_history_id`.
- **Incremental** (hourly): today's state at `T = now` replaces today's state rows (a combination with no data now is zeroed, only where it was not zero; nothing is rewritten when nothing changed); flow, executions and decisions of yesterday and today are recomputed (a late row heals before the close); SBOM is upsert-only (a stored SBOM day is a snapshot the view could not rebuild).
- **Close** (`mode: close`, `day` before today): see section 1 for the state; the day's flow, executions, decisions and SBOM are recomputed. An `incremental` message for an earlier day (consumed after midnight) is that day's close.
- **Backfill** (`from`, `to`, optional `reason`): clamped to the retention floor and to today; batches of 45 days (`backfillBatchDays`), one run row per batch (`day` = batch start, `range_to` = batch end), a pause between batches (`throttleMs`, default 250 ms, interruptible by shutdown); **resumable**: a batch fully covered by a succeeded backfill run of the same time zone is skipped (not for `timezone_changed` or `repair`, which recompute everything). **One tenant per message**; the consumer's prefetch bounds concurrency.
- **Rebuild** (`reason: timezone_changed`): the range is cleared through the SECURITY DEFINER function, then recomputed as a backfill in the tenant's CURRENT zone (read from the database).
- **Purge** (the tick, once per 24 hours per process): `qm_reporting_purge` in bounded calls (5,000 rows per table per call, at most 20 calls): rollup rows older than the retention months (`REPORTING_ROLLUP_RETENTION_MONTHS`, 25), run rows and export rows older than 13 months; a running run is never purged.
- **Idempotency:** every upsert is keyed by the natural primary key and rewrites a row only when a counter differs (`IS DISTINCT FROM`), so a repeated message changes nothing, `computed_at` included (`RPT-S09a`). Replacing a day zeroes only the stale combinations.
- **Tenant isolation:** the tenant comes from the ENVELOPE; a payload naming another tenant is non-retryable `ownership_mismatch`; the handler re-reads the tenant (usable status, valid time zone) from `report_tenant_settings_v`; the repository takes `tenantId` first in every method, refuses a row that names another tenant, and the composite key of the database refuses a mismatched workspace, repository or pipeline (`RPT-S09b`). Every value is a bind parameter (the only interpolated text is a constant table or column name of `store.js`, and the validated integer of `SET LOCAL statement_timeout`).
- **Failures:** each run writes a `report_rollup_runs` row (`running`, then `succeeded` with `rows_written` and `as_of_history_id`, or `failed` with a stable code). `ROLLUP_ERROR_CODES`: `ownership_mismatch`, `invalid_range` (also an unknown mode or time zone) and `internal` are NON-retryable (`NonRetryableError`, dead-letter); `source_unavailable` (a connection error, a deadlock, a serialization failure) and `timeout` (a statement timeout) are RETRYABLE (`TransientError`). `source_unavailable`/`timeout` retry with the worker's policy.
- **Statement timeout:** every transaction of the repository starts with `SET LOCAL statement_timeout = 60000` (`ROLLUP_STATEMENT_TIMEOUT_MS`), proved by `RPT-S09c`.
- **Role:** the worker already builds the repositories on `REPORTING_DATABASE_URL` (the login member of `qm_reporting`) and falls back to the shared pool in development with a warning (A0's `index.js`, unchanged). The checks run the whole path on a real login of `qm_reporting` that is not a superuser.
- **Tick** (`REPORTING_ENABLED` true only; with the flag off `startRollupTick` returns null): hourly, per usable tenant (`active`, `trial`), through the outbox with deterministic ids `reporting-rollup-<tenant>-<mode>-<day>-<epoch hour>` (so a second scheduler instance or a repeated tick queues nothing): one `incremental`; one `close` of the previous tenant-local day **until a close of that day has succeeded** (so it goes out right after each tenant-local midnight and repeats hourly only while it has not succeeded); and, for a tenant that has history and no run at all, one `backfill` (`first_enablement`) from its oldest history day (capped at the retention) to today. A tenant with an invalid stored time zone is skipped with a warning.
- **Operator command:** `REPORTING_ENABLED=true node packages/db/scripts/reporting-backfill.js --tenant <slug|id> [--from] [--to] [--reason] [--allow]` queues one backfill message; refuses without the flag, in production without `--allow`, for an unknown or inactive tenant; prints ids only.

## 4. Optional additions to the frozen signatures (all additive and optional)

`upsertFindingsDays({ tenantId, rows, replace: { days, groups: ["state" | "flow"] } })` and `upsert{Executions,Decisions}Days({ tenantId, rows, replaceDays })` (zero the stale combinations of the given days); state rows carry `severityExact`; the state and flow arrays carry a non-enumerable `asOfHistoryId`. A findings row carries ONE counter group or both; the upsert writes only the group a row carries, which is how a backfill avoids zeroing a state snapshot. The compute methods return `tenantId` on each row (the upserts accept the row without it and refuse one that names another tenant). The state method returns only keys with an open finding or an exception in force (sparse).

## 5. Measured (2026-11-26; an ephemeral local PostgreSQL 18 with `fsync=off`, one machine, the handler called in process on the shared pool as the owner; no broker)

| Dataset | Run | Time |
|---|---|---|
| The 120-finding seed (`seed:findings --scale small`), tenant `demo` | hourly incremental | 222 ms |
| | 90-day backfill, recomputing (`repair`) | 247 ms |
| 100,000 findings (SQL generator `buildBulkDataset`: `new`, a third fixed pending verification, half of those verified, about 150,000 history rows over 120 days; 6,000 blocked or skipped executions) | hourly incremental (state at `now` over 100,000 findings, plus yesterday and today) | 1.31 s |
| | **90-day backfill (first, 2 batches of 45 days)** | **1.83 s** |
| | 90-day backfill, recomputing (`repair`) | 2.28 s |

Far below the 2 minute target. The limits of the measurement: the dataset has no review, exception or advisory rows, the clock was one machine, the worker used the owner connection (the suite runs the same code on a real `qm_reporting` login, correctness only, not timing), and a real tenant has more history rows per finding than the generator wrote.

## 6. Verification record

Run on 2026-11-26 in the worktree: `pnpm lint` 0 errors (only warnings that already exist on main, none in Part A files); `pnpm build --force` 2 of 2 tasks; `npx prettier --check apps packages` clean; `pnpm install --frozen-lockfile --offline` up to date; `pnpm --filter @qmentisai/api contract:parity` 0 differences (no route added); `pnpm test:security` **1045 tests, 1045 passed, 0 failed** (baseline 1036, plus the nine checks `RPT-S09a` to `RPT-S09d` and `RPT-S10a` to `RPT-S10e`, so 1026 checks). The nine checks were also run alone against a scratch database before the whole suite; mutations (an upsert that rewrites unchanged rows, UTC day buckets, a disabled override flag) each made the intended check fail.

## 7. Limits and known gaps

1. Severity series forward-only, flow severity attribution, SBOM history, SLA of a past `T`: section 1 and 3.
2. `eligible_count` is an approximation of "trusted, default branch, complete": succeeded, full, trusted, a branch ref, at least one complete result and no incomplete one (the view carries no branch name).
3. `result_complete_count` and `result_partial_count` sum the scan results of the day's executions (any scan type).
4. `components_vulnerable` counts components with an OPEN SCA finding of the same pipeline and purl at computation time (not as of the SBOM day).
5. No live proof against RabbitMQ: the tick's outbox rows and the handler are proved in process; the relay and the consumer were not started.
6. The 100,000-finding dataset has no review, exception or advisory rows (`new`, a third fixed pending verification, half of those verified); the decision series is measured on the seed and the rich dataset only.
