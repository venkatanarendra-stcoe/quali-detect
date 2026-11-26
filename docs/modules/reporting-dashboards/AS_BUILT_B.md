# Reporting and Dashboards, Part B (the read API): as built

**Built:** 2026-11-26 on `16486ff` (Part A0), in a worktree branch, not pushed. **Scope:** `SPEC.md` 9 (the thirteen read endpoints), 7.1 (read path), 12 item 7 (read role), 17 D-2 and D-4, `ADR-015`, and the lead's brief for Part B. Everything is OFF behind `REPORTING_ENABLED=false`. Not verified here: see section 9.

## 1. What was built, by directory

| Directory | Files (all new unless marked) |
|---|---|
| `packages/db/src/reporting/read/` | `index.js` (filled: `buildReadMethods`, all 16 frozen methods), `tx.js` (read-only transaction wrapper, `uuid`/`day` guards, the open-status SQL list), `posture.js` (`getTenantSettings`, `getRollupFreshness`, `getPosture`, `getPostureAsOf`), `findings-metrics.js` (`getTrends`, `getRemediation`, `getSla`, `getAging`), `scan-metrics.js` (`getScanActivity`, `getCoverage`, `getSbom`), `quality-metrics.js` (`getQuality`), `breakdown-metrics.js` (`getBreakdown`, `getTopRisk`, `getWorkload`, `getOverview`) |
| `apps/api/src/modules/reporting/` | `routes/read.routes.js` (filled), `controllers/read.js`, `services/read.js`, `mappers/read.js`, `schemas/read.js`, `policies/read.js`, `read-repository.js` (the repository over the lazy read client), `read-cache.js` (cache, epoch, epoch bumper, close hook) |
| `apps/api/src` (three small edits) | `app.js`, `realtime/consumer.js`, `realtime/index.js`; see section 5 |
| `apps/api/test/security/helpers/reporting/` | `reporting-b-checks.js` (11 checks), `reporting-b-fixtures.js` (the data, the API on a stub authentication chain, an in-memory Redis double), and the `B: 11` line of `expected.js` |
| `docs/modules/reporting-dashboards/` | this file |

No frozen file was edited. Nothing under `docs/api/` was touched (the lead regenerates it).

## 2. The endpoints

All thirteen are under `/api/v1/reporting/`, audience `tenant`, rate-limit profile `read`, the standard envelope, Zod `.strict()` query and response (the frozen `REPORTING_ROUTE_SCHEMAS`), OpenAPI through the route kit. `meta` is `{ asOf, source, stale, timeZone }` plus `correlationId` (and `formula` on `top-risk`). A weak `ETag` over the DTO (not the meta) and `Cache-Control: private, no-cache` are sent, and `If-None-Match` answers `304` after authorization and the read.

| Route | Key | Source | Notes |
|---|---|---|---|
| `posture` | `finding.view` | live | P-1 to P-9 from one grouped query; P-10 `pipelinesHealthy` only for a caller with `execution.view` (otherwise `null`); `asOf=YYYY-MM-DD` reads the daily rollup |
| `trends` | `finding.view` | rollup | zero-filled day axis (`listDays`), gap days marked, linear projection per T-3 |
| `remediation` | `finding.view` | live + rollup | R-1 (median, p90, mean via `percentile_cont`), R-3, R-7 live; velocity and reopen rate from the rollup |
| `sla` | `finding.view` | live | R-5 against one `now`; R-4 over the last 30 days |
| `aging` | `finding.view` | live | R-6 buckets and the ten oldest critical and high |
| `scan-activity` | `execution.view` | rollup + live | S-1, S-2, S-6, S-7 from `report_daily_executions`; S-3 (duration, queue wait) live |
| `coverage` | `execution.view` | live | S-4 and S-5 as OBSERVED (section 7) |
| `sbom` | `execution.view` | live + rollup | latest SBOM from `report_sbom_latest_v`, trend from `report_daily_sbom` |
| `quality` | `security_review.view` | live | Q-1 to Q-6 over `report_decisions_v` and `report_advisories_v`; a rate over fewer than 20 decisions has `rate: null, tooFew: true` and the counts |
| `breakdown` | `finding.view` | live | by repository, pipeline (soft-deleted ones grouped as "(deleted)"), scan type or rule; keyset pages with an HMAC-signed cursor bound to tenant, workspace and dimension |
| `top-risk` | `finding.view` | live | shared `computeRiskScore` and `compareTopRisk`; the formula in `meta.formula` |
| `workload` | `finding.assign` | live | per assignee, display name only (no e-mail), never ranked; `unassigned` count |
| `overview` | `dashboard.view` (tenant) | live + rollup | no workspace or tenant parameter (400); only the caller's visible workspaces, and per workspace only the sections whose key the caller holds there (`null` otherwise); a hidden workspace is absent, never zero |

`meta.source` is `rollup` when any part of the answer comes from the daily rollups (then `asOf` is the last successful run and `stale` is true when that run is older than two hours, or when no run exists), otherwise `live` (asOf now, never stale). An empty rollup is not an error: the answer is the gap-marked or zero-filled shape with `stale: true`.

**Authorization.** The workspace routes use `inWorkspace(key, reportingWorkspaceScope)` (the Findings pattern): the workspace is loaded by tenant AND id, so another tenant's, a hidden and a nonexistent workspace are the same 404; a visible workspace without the key is 403. While `REPORTING_ENABLED` is not `true` every scope resolver answers `null`, so each route is the same 404 as a route that does not exist (checked byte for byte), after authentication and validation only (an invalid query on a disabled route still answers 400: the route kit has no hook before validation). Findings has no master flag to mirror (only `FINDINGS_AGENT_ENABLED` for the agent), so the flag lives in the resolvers; this also keeps the routes in the OpenAPI document and in the contract snapshot (which reads the permission from the literal `inWorkspace("key", ...)` source).

## 3. Queries

Parameterized SQL only (Prisma tagged templates; the only interpolated SQL text is the allow-listed open-status list and the allow-listed grouping expressions chosen by the validated `by`). Every statement carries the tenant AND the workspace (or `workspace_id = ANY(...)` for the overview). Each repository call runs in ONE `REPEATABLE READ, READ ONLY` transaction on the read pool with `SET LOCAL statement_timeout = 5000` (the role's value, set again so a development database on the shared pool is bounded too); no statement locks. Only the `report_*_v` views and the `report_*` tables are read (the suite runs every endpoint as `qm_reporting_ro`, so a source-table read would fail). Two read transactions run in parallel in one call, in `getRemediation` (R-3, the heaviest statement, in its own transaction).

Definitions chosen where the SPEC leaves room: open statuses and lifecycle groups from `@qmentisai/shared` (never redefined); SLA states against one `now` with the Findings formulas (`due_soon` at 25 percent remaining); the closed-findings SLA (R-4) uses `sla_started_at` plus the SHARED DEFAULT target hours (section 7, item 2); aging buckets by whole days since `first_detected_at` (0 to 7, 8 to 30, 31 to 90, over 90); R-1 and R-7 take findings whose `verified_at` falls in the period; R-3 takes the first review of a finding when it falls in the period; Q-5 "confident" is advisory confidence 80 or more (the Findings band); the reopen rate (R-8) uses the same 20-sample rule as the decision rates.

## 4. Cache (D-4)

`read-cache.js`: `createCache` (namespace `rpt`), key `qmentis:t:<tenant>:cache:rpt:<workspace>.<metric>.<epoch>.<paramsHash>` with the tenant from the SESSION, the validated parameters hashed, and the permission SHAPE in the hash where the answer depends on it (`execution.view` for posture; the visible workspaces and their section keys for the overview). TTL 30 s for answers that contain any live part, 300 s for the pure rollup answers (`trends`, the as-of posture). The EPOCH is a Redis counter per (tenant, workspace) and one tenant-wide counter (for the overview), read BEFORE the key is built; an unreadable epoch means no cache for that request. The epoch bumper (`createReportingEpochBumper`) increments both counters in one `MULTI` on a verified `finding.*` hint; a failure is logged and swallowed. Redis down, slow (500 ms bound) or absent serves uncached and never fails the request.

Integration facts a reader needs:
- The frozen `ReportingRouteDeps` carries no Redis, so the read cache opens its own lazy connection from `config.infra.redisUrl` (one per process, closed by `disconnectReportingReadCache()` in the application close hook). `config.reporting.cacheRedis` is a TEST SEAM (an injected client; the production config has no such key).
- The epoch moves only when the realtime hint consumer runs (`REALTIME_ENABLED=true` and RabbitMQ); without it the live entries expire by their 30 s TTL (the bound the SPEC already accepts). The bump is made from the DATABASE row the hint resolver verified (tenant and workspace), never from message fields.

## 5. The three small edits outside the module (exact)

1. `apps/api/src/app.js`: two imports after the `createRealtime` import (`disconnectReportingReadClient` from `./modules/reporting/index.js`, `disconnectReportingReadCache` from `./modules/reporting/read-cache.js`) and two lines in `close()`, between `await realtime?.close();` and `await closeInfrastructure();`: `await disconnectReportingReadClient();` and `await disconnectReportingReadCache();`.
2. `apps/api/src/realtime/consumer.js`: `createHintHandler({ resolver, realtime, onFindingChanged })` takes an optional `onFindingChanged(target)` and, after `realtime.emit(hint)`, calls it with `{ tenantId, workspaceId }` of the resolved target for a finding hint type, swallowing its errors; `createRealtimeConsumer` takes and forwards `onFindingChanged`.
3. `apps/api/src/realtime/index.js`: passes `onFindingChanged: createReportingEpochBumper({ redis: infra.redis, enabled: config.reporting?.enabled === true, log: logger })` to `createRealtimeConsumer` (and one import).

`realtime/findings.js` was not changed: the hint is built there, the epoch bump is in the handler that already holds the verified target.

## 6. Security suite (ADR-008 area 20; the `B` line of `expected.js` is 11)

| Check | Proves |
|---|---|
| `RPT-S01` | 12 workspace reads: another tenant's, a hidden and a nonexistent workspace give the identical 404 body; tenant B reading A is the same 404; `tenantId` in the query is 400; unauthenticated is 401; the overview refuses `workspaceId` and `tenantId` (400); every denial has its 200 control |
| `RPT-S01b` | module OFF: all 13 routes are byte-identical to an unknown route's 404, and the read database is never opened; module ON controls |
| `RPT-S02` | 7 built-in roles plus a custom role against all 13 endpoints: 200 exactly when the role holds the key (expected table written out in the check from SPEC 3, independent of the bundles), 403 otherwise, never 404 |
| `RPT-S02b` | the overview: Admin only; a one-workspace caller sees only that workspace (the hidden id is absent from the body, the totals and the top risk); sections without a key are `null`; tenant B sees only B; workload only for `finding.assign`, display names only |
| `RPT-S03` | 39 responses (all endpoints, both workspaces, tenant B, every breakdown dimension and a second page, every trend series, as-of posture): strict schema parse of data and meta, no `FORBIDDEN_REPORTING_DTO_KEYS` at any depth, no canary (planted in evidence snippet, scm ref, URL, rationale, comment, advisory reasoning, exception justification and controls; plus a control that they exist), no foreign or own tenant id, no e-mail |
| `RPT-S03b` | hostile input: unknown key, period twice, bad preset, over 400 days, future end, bad series or dimension, injection-shaped values, limit range, as-of today or not rolled up (409), tampered or foreign cursors (400 `INVALID_CURSOR`); controls succeed |
| `RPT-S04` | all 16 repository methods run as `qm_reporting_ro` (the suite's read client is `SET LOCAL ROLE qm_reporting_ro`); as that role findings, evidence, reviews, comments, exceptions, advisories, users, executions and `tenant_llm_settings` are refused and every write to a report or source table is refused |
| `RPT-S04b` | the read transaction is `repeatable read`, read only, 5 s timeout, refuses a write (control: a plain transaction accepts it); the statements of all methods are recorded: only SELECT, no write or lock verb, tenant filter everywhere, workspace filter on workspace statements |
| `RPT-S11` | cache scoping: two tenants asking the overview with identical parameters, two workspaces with identical parameters, callers with different `execution.view` or visible workspaces never share an entry; key shape; no key holds another tenant's id |
| `RPT-S11b` | the epoch is read before the key; a cached answer is served until the hint, then ONE bump (the REAL `createHintHandler` on a `finding.created` message) invalidates it while another workspace and another tenant keep theirs; a non-finding message and a disabled module do not move it; Redis down does not fail the bump |
| `RPT-S11c` | Redis failing or hanging: all 13 endpoints still 200 with identical data, nothing stored, about the same latency; recovery uses the cache again; no Redis at all is 200 |

Mutation sanity: removing the permission shape from the overview cache key makes `RPT-S11` fail (done once by hand). Metric VALUES are not asserted in the suite (area 20 leaves them out); they were checked by hand on the hand-built dataset (posture counts, SLA states, the 54-point top-risk score, R-1 median 26.5 and p90 33.3 days, the 20-decision rates).

## 7. Findings about frozen files (not edited; workarounds in place)

1. **No view exposes repositories or pipelines as such** (no `enabled` flag, no scan-type configuration, no repository connection state). Consequences: P-10 counts pipelines that finished a run in the last 90 days (not "enabled pipelines"); coverage lists only repositories that have an execution (reasons produced: `no_pipeline` (every pipeline deleted), `no_recent_scan`, `last_scan_partial`; NOT produced: `pipeline_disabled`, `connection_unavailable`); S-5 `enabled` means "observed" (open findings of that type, or an SBOM) and `lastComplete` is only known for the SBOM; the GitHub connection tile of C-4 and O-5 cannot be served (and the frozen posture DTO has no field for it). Patch proposal: a `report_pipelines_v` (tenant, workspace, repository ids and names, pipeline id and name, `enabled`, `deleted`, the enabled scan types of the current version, the repository connection state) plus a grant to both roles.
2. **Tenant SLA targets are not readable** (`finding_sla_targets` is in no view) and `sla_due_at` is cleared when a finding closes, so R-4 uses the shared defaults (`SLA_DEFAULT_HOURS`) and ignores a tenant override. Patch proposal: a `report_sla_targets_v` (tenant, severity, hours) or an `sla_target_hours` column on `report_findings_v`.
3. **The rollup has no per-status counts**, and the frozen posture DTO needs all 12 statuses and 7 groups, so the as-of posture fills `fixed_pending_verification`, `awaiting_verification` and `accepted_or_suppressed` (the counters the rollup keeps) and leaves the other statuses and groups at 0, `expiringWithin30Days` 0 and `awaitingDecision` 0, `newLast24Hours` null. A 0 there is "not rolled up", not "none". Patch proposal: make those fields nullable in `postureDtoSchema` (or add a `partial: true` flag) so the UI can say so.
4. **`trendPointSchema` has no `null`**: the gap marker (a day no rollup run touched) is a point that carries only `day` (every series key absent), never a 0. A covered day without rows is a real 0 (the rollup is sparse). Patch proposal: allow `null` per series key if an explicit `null` is preferred.
5. **`severityBackfilled`** has no source in the frozen surface; it is true when a succeeded `backfill` run touches the requested period. Part A must confirm that it writes severity rows in a backfill only when the equivalence proof held (ADR-015 item 3), or give the API another signal.
6. **`ReportingRouteDeps` has no Redis**, hence the dedicated cache connection (section 4).
7. **`report_decisions_v`** joins every review to its finding, so any read of decisions hash-joins the whole findings table (the R-3 plan below). Patch proposal: expose `first_detected_at` on the review rows, or a `report_first_decisions_v`.
8. `report_executions_v` has no default-branch flag: "recent successful default-branch scan" is a succeeded, trusted, branch-ref execution in the last 30 days (a non-default branch counts).

## 8. Performance (SPEC 14), measured

Dataset: one tenant, one workspace with **100,000 findings** (generated with `generate_series`; about 52 percent open, all severities and types, SLA clocks set), 3 repositories, 6 pipelines, **20,000 approved reviews**, **20,000 executions** over 90 days, 400 days of rollup rows (6 pipelines x 3 types x 5 severities x 400 days = 36,000 rows) and 400 close runs. PostgreSQL 18 on the development machine (fsync off, an ephemeral cluster, `ANALYZE` run), the API on a stub authentication chain acting as `qm_reporting_ro`, cache OFF (no Redis), sequential calls over HTTP, 3 warm-ups then 30 timed samples (p95 is the 29th of 30). Not a load test: one connection at a time.

| Endpoint | p50 ms | p95 ms | Target |
|---|---|---|---|
| posture (P-1 to P-10) | 177 | **215** | p95 under 300 live: met |
| trends 90 d (rollup) | 32 | 39 | under 200: met |
| remediation 90 d | 340 | **411** | under 500: met |
| sla | 237 | 252 | |
| aging | 193 | 221 | |
| scan-activity 90 d | 108 | 135 | |
| coverage | 175 | 205 | |
| sbom 90 d | 28 | 37 | |
| quality 90 d | 292 | 366 | none stated |
| breakdown repository, pipeline, rule | 118, 125, 104 | 150, 146, 124 | |
| top-risk | 86 | 100 | |
| workload | 98 | 135 | |
| overview 30 d | 147 | 170 | |

Before two changes the same run gave posture p95 289 ms and remediation p95 606 ms (over the 500 ms target): (a) group by the enum columns instead of their text casts (the planner then aggregates per worker instead of sorting 100,000 rows: 154 to 108 ms for the posture statement), and (b) R-3 in its own parallel read transaction (it is the heaviest statement; the call now costs the longer of the two transactions, not their sum). A cached answer costs one Redis round trip.

The two slowest statements (`EXPLAIN (ANALYZE)` on the 100,000-finding workspace):
- **R-3, time to first decision, 273 ms:** `report_decisions_v` (review branch) hash-joins 20,000 reviews to a sequential scan of all 100,000 findings (to carry `scan_type`), is semi-joined to itself for the window, then 20,000 index lookups into `findings`, `pipelines` and `repositories` for `report_findings_v` (to read `first_detected_at`). Parallel Hash Semi Join, Hash Join, Index Scan using `findings_pkey` (loops=20000), Sort of 20,000 rows. No index helps a hash join over the whole table; the fix is the view change in section 7 item 7. The call is hidden by the parallel transaction and by the 30 s cache.
- **Posture grouping, 108 ms:** Parallel Seq Scan on `findings` (100,000 rows, filter tenant and workspace) hash-joined to `pipelines` and `repositories` (the view's joins; Memoize makes the repository lookup cheap), partial GroupAggregate per worker, Gather Merge. The Findings indexes lead with `(tenant_id, workspace_id, status, ...)`, but the statement reads every status (P-4 counts all 12), so a scan is the right plan; an index would not change it. Index proposal only if the p95 ever exceeds the target: none needed now. The next cost is the P-10 statement (35 ms: a Bitmap Heap Scan of the 20,000 executions through `executions_tenant_id_pipeline_id_concurrency_group_status_idx`); a covering index `(tenant_id, pipeline_id, requested_at DESC) INCLUDE (status, workspace_id)` on `executions` would make it an index-only scan (proposal, not applied).

## 9. Not verified

- The browser and the UI (Part D): nothing renders these routes yet.
- A real Redis (the suite and the measurements use an in-memory double and no Redis): key syntax with a real server, `MULTI` semantics, eviction, the 500 ms bound under a real network stall.
- The epoch bump through a real RabbitMQ hint (the real hint HANDLER is exercised with a verified target, the broker is not); the epoch is not bumped when `REALTIME_ENABLED` is off.
- A real provisioned `qm_reporting_ro_login` connection from the API (the suite uses `SET LOCAL ROLE` of the same group, which proves the grants; the login's own role settings are proven by the A0 suite).
- The rollup VALUES: Part A is not built, so every rollup-backed answer was read from hand-inserted rows; the equivalence of the as-of posture with the live one is Part A's gate.
- Concurrency and load: one request at a time; the read pool size, the parallel transaction in `getRemediation` under many callers, and a cache stampede were not measured.
- Time zones other than UTC end to end (the period helpers are Part A0's and tested there; the read paths pass `from`, `to`, `start` and `endExclusive` through unchanged).
- `contract:snapshot` was NOT run (it writes `docs/api`, which the lead regenerates). The operation diff against the committed OpenAPI document was computed by booting the application the way the snapshot does and comparing operations: exactly the 13 reporting `GET` operations are added and none removed; the static permission extraction the snapshot uses was reproduced on the route sources and finds all 13 keys and scopes.
