# ADR-015: Reporting rollups, structural redaction and export design

- **Status:** **Accepted (2026-11-26, owner decision D-1 to D-5, C-1 to C-4 of `docs/modules/reporting-dashboards/SPEC.md` 17).**
- **Date:** 2026-11-26
- **Decision owners:** Product owner (decision); Claude Code (proposal)

## Context

The Reporting and Dashboards module needs current posture, trends, remediation and scan metrics, and exports, over data that already exists (findings, the immutable finding history, reviews, advisories, executions, scan results, SBOM items). Three pressures meet: trends over 90 days and more per severity and per day cannot be answered live from the primary without cost to the transactional path; a report must never leak evidence, a rationale, a comment or a secret; and the platform has no tenant time zone, no export mechanism and no PDF writer.

## Decision

1. **Hybrid read model.** Current-state tiles are **live** read-only queries over the Findings partial indexes. Trends, breakdown series and point-in-time views read **daily rollup tables** (`report_daily_findings`, `report_daily_executions`, `report_daily_decisions`, `report_daily_sbom`), keyed by tenant, workspace, repository, pipeline, tenant-local day. Percentile metrics (time to remediate, time to first decision, duration) are computed live over a bounded window because percentiles cannot be merged from rollups.
2. **Derived data is disposable.** Rollups, report-run rows and generated files can be deleted and rebuilt from the sources; nothing derived is read by a transactional write path; the module changes no source table's meaning and adds no write inside a finding transition (rejected: counters maintained by the transition function).
3. **One function, three uses.** "State as of instant T" (the latest history row per finding with `created_at <= T`, the effective severity in force at T) is the single computation behind the hourly incremental run (`T = now`), the day close (`T = end of the tenant-local day`) and the **backfill** over past days. An **equivalence test** (live posture against `asOf(now)`, a backfilled day against the incremental day, a rebuild after a time-zone change against a fresh build) is a gate. **If the severity reconstruction is not exact, the severity trend is forward-only** (the backfill still produces status, flow and execution series; the severity series starts at the first run). The owner ruled this on 2026-11-26.
4. **Where it runs.** A new worker role `reporting` and queue `reporting` (versioned envelope, ADR-011); the scheduler worker ticks hourly and emits one `reporting.rollup.requested` per active tenant; every handler re-validates tenant ownership and is idempotent (upserts). Everything is behind `REPORTING_ENABLED=false` by default.
5. **Structural redaction.** Reports and rollups read **only** through the `report_*_v` views, which expose ids, enums, timestamps, counts, the already-redacted title, rule id, path and line numbers, component fields, severity, status and SLA columns, and exclude evidence, rationales, comments, advisory reasoning, exception justifications, secret previews and e-mail addresses. Two least-privilege roles: `qm_reporting` (worker: `SELECT` on the views, `INSERT`/`UPDATE` on `report_*` tables) and `qm_reporting_ro` (API read pool: `SELECT` only, read-only transactions, `statement_timeout`), each a `NOLOGIN` group with a separate login created by an idempotent provisioning script (the `qm_fp_agent` pattern). A canary test plants a fake secret in every excluded field and asserts absence from every rollup row, DTO, CSV and PDF.
6. **Tenant reporting time zone.** `tenant_settings.reporting_timezone` (IANA, default `UTC`); one zone per tenant; a change triggers an exact rebuild.
7. **Exports.** Asynchronous only (`202`, a `report_exports` row, an outbox message); CSV (with formula-injection neutralisation) and PDF drawn by **pdfkit** (pure JavaScript, MIT, text and vector charts, no HTML rendering, no browser, no native binary); stored under `reports/{tenantId}/{reportId}.{ext}` built by the server from validated ids; **authenticated download through the API**, no bearer or signed URL; 30-day file retention; limits: **CSV 250,000 rows, 3 concurrent jobs per tenant**, a per-user hourly request limit; a request over a limit is refused, never truncated.
8. **Authorization.** No new permission key. `report.view` (all built-in roles, owner ruling C-2), `report.export` (Admin, Manager, Lead), `dashboard.view` (tenant scope, Admin) for the Organization Overview and tenant-wide reports, section keys per workspace. 404 for another tenant's or hidden workspace, 403 for a missing key in a visible workspace.

## Alternatives considered

1. **Live queries only:** no new tables, but a per-request reconstruction of history for 90 days by severity is a window query over the whole history; rejected for cost and for the severity-as-of problem.
2. **Materialized views:** full refresh, no incremental, no backfill story, no tenant-time-zone buckets; rejected.
3. **Counters in the transition function:** real time, but puts reporting work in the transactional path and couples Findings writes to this module; rejected (RPT-015).
4. **Headless Chromium or pdfmake for PDF:** a browser is large and needs its own sandbox (and the Docker/CI scope limits apply); pdfmake adds layout dependencies on top of pdfkit that the fixed report templates do not need; rejected.
5. **Signed expiring URLs:** a bearer link is a leak path; rejected for an authenticated stream.

## Rationale

The hybrid keeps current numbers exact and cheap and keeps history-derived trends off the primary; structural redaction removes a whole class of leak by making the sensitive columns unreachable to the reporting code rather than filtering them; one as-of function with an equivalence test keeps the live and rolled-up numbers honest.

## Consequences

### Positive
- Fast trends and point-in-time views, survival of the 13-month execution purge (rollups 25 months), exact backfill from immutable history, no load on the transactional path, a testable no-leak guarantee.

### Negative / trade-offs
- New tables, worker, queue and two roles to operate; an equivalence test to maintain; a rebuild cost on a time-zone change; one new dependency (pdfkit); the severity trend may be forward-only if reconstruction is not exact.

## Security and operational impact

- Tenant and workspace on every key, composite foreign keys, cache keys with the tenant and an invalidation epoch, object paths built by the server, audit entries for generate, download, delete and time-zone change, no value in any log.
- Operations: rollup lag, run duration, export outcome and queue depth metrics; an alert on lag over two hours.

## Related documents

- `docs/modules/reporting-dashboards/SPEC.md`, `SCREENS.md`; ADR-003, ADR-004, ADR-008 (area 20), ADR-011; `docs/modules/findings/SPEC.md` (history, SLA, advisories); `docs/modules/executions/SPEC.md` (ER-17).
