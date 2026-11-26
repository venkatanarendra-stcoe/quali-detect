# Reporting and Dashboards: live test plan for the owner

Written 2026-11-26 for Part E. Everything here is what the security suite and the build CANNOT prove, because it needs the owner's machine (a broker, a password-authenticated database login, a real Redis, the development database, a human). Each gate has an id (R-1 to R-8), exact steps, the expected result and a place to record the outcome. Nothing in this file has been run. Never paste a credential into a ticket or a log; the steps below read secrets from your own `.env` and never print them.

Prerequisites: the migrations are applied (`pnpm --filter @qmentisai/db db:migrate:deploy`), the API and workers start, and a tenant with at least one workspace, repository, pipeline and a few findings exists. `REPORTING_ENABLED=true` for the API and the reporting worker; `ARTIFACT_STORE_ROOT` is an absolute path both processes can reach.

## R-1 Real RabbitMQ round trip through the reporting queue and the scheduler tick

1. Start RabbitMQ, the outbox relay, the API and `apps/workers` reporting entry (`node apps/workers/src/reporting/main.js`) with `REPORTING_ENABLED=true`.
2. Watch the worker log. Within the first minute the tick logs `reporting tick queued the rollups` with `tenants` and `queued` greater than 0. In the RabbitMQ management UI the `reporting` queue shows messages published and consumed (the dead-letter queue stays empty).
3. In psql: `SELECT mode, status, day, rows_written FROM report_rollup_runs WHERE tenant_id = '<tenant>' ORDER BY started_at DESC LIMIT 5;` Expect a `succeeded` incremental run for today (and a close run for yesterday after local midnight).
4. Request a report from the UI (or `POST /api/v1/reporting/reports` with an `Idempotency-Key`). Expect 202, then the report turns `ready` and downloads.
5. Restart the worker and repeat the tick: no duplicate rows (the message ids are deterministic).
Expected: queue consumed, run rows succeeded, report ready, no dead letters. Record: date, result, anything unexpected.

## R-2 The provisioned qm_reporting and qm_reporting_ro logins over a password-authenticated connection

1. Run `node packages/db/scripts/provision-reporting-logins.js` (see its header; it reads a role password from the environment and prints nothing secret) as a role that may create roles.
2. Set `REPORTING_DATABASE_URL` (worker, `qm_reporting` login) and `REPORTING_RO_DATABASE_URL` (API, `qm_reporting_ro` login) in your `.env`, with the passwords you chose. Production refuses to start without them.
3. Over a real password connection, as the read login: `SELECT count(*) FROM report_findings_v;` works; `SELECT count(*) FROM findings;` fails with permission denied; `UPDATE report_daily_findings SET open_count = 0;` fails; the transaction is read-only and a statement over 5 seconds is cancelled.
4. As the worker login: an `INSERT` into `report_rollup_runs` works; `DELETE FROM report_daily_findings` is denied; `SELECT qm_reporting_clear_range(...)` works; `SELECT * FROM findings` is denied.
5. Start the API and the worker with the URLs set: no "shared pool" warning is logged and the reads and a rollup succeed.
Expected: every allowed statement works and every denied one fails with permission denied. The suite proves the grants with `SET LOCAL ROLE`; this proves the login, password authentication and the per-role settings.

## R-3 A real Redis cache and the epoch bump from a finding transition

1. Run Redis and set the Redis URL of the API. Open the dashboard and read the posture; read it again within 30 seconds (the second call is a cache hit: with `redis-cli MONITOR` you see `GET` of a `rpt:` key).
2. Move a finding through a transition (for example approve a review). With `REALTIME_ENABLED=true` and RabbitMQ up, the findings hint handler bumps the tenant epoch (`redis-cli GET` of the epoch key increases) and the next posture read is a MISS with the new counts.
3. Stop Redis: the dashboard still answers (a miss path within the 500 ms bound), and recovers when Redis returns.
4. Confirm keys carry the tenant id (no key without one).
Expected: hit, then a miss with fresh numbers after the transition, graceful degradation without Redis. The suite uses an in-memory double.

## R-4 First-enablement backfill on the development database

1. Back up the development database (`pg_dump`). Do not run this against a database you cannot restore.
2. With `REPORTING_ENABLED=false`, confirm no `report_rollup_runs` rows exist for the tenant, then set it `true` and start the worker.
3. The first tick queues a `backfill` message with `reason: first_enablement` from the earliest history day (capped at 25 months). Watch `report_rollup_runs` grow in batches of mode `backfill`, all `succeeded`, and the log show throttling.
4. Compare: the sum of `new_count` in `report_daily_findings` for a past week against `SELECT count(*) FROM finding_status_history WHERE from_status IS NULL AND created_at` in that week (tenant-local days).
5. Open the trend chart: the flow series is filled for the history; the backlog and severity series are EMPTY before today (forward-only by design).
6. Measure the extra load on the transactional database during the backfill (`pg_stat_activity`), and that ingestion is not slowed noticeably.
Expected: complete backfill, equal counts, forward-only state series, no visible effect on ingestion.

## R-5 A PDF reviewed by a human

1. Generate each PDF template (executive summary, findings by pipeline, SLA compliance, remediation performance, detection quality, point-in-time snapshot) for a workspace with realistic data, including a finding whose title contains a long unbroken word, right-to-left text and an emoji.
2. Open each in two viewers (a browser viewer and a desktop one). Check: no clipped or overlapping text, readable tables across page breaks, the header/footer, the data-as-of line and the coverage statement, the severity colors independent of each other, readable in grayscale, a page count under 40.
3. Select and copy text: it is selectable and contains no secret, e-mail address or evidence snippet.
Expected: a human judges the layout acceptable. The suite proves the bytes are safe and redacted, not that the pages look right.

## R-6 Human and screen-reader review of the charts

1. With keyboard only: tab through every chart and tile of the Reporting pages; focus is visible, order logical, no keyboard trap.
2. With a screen reader (NVDA, VoiceOver or Orca): each chart exposes a title, a text summary and a data table alternative; a null (unknown) day is announced as unknown, not zero.
3. Check contrast of the chart colors against the design tokens in light and dark mode, and that no meaning depends on color alone (patterns, labels, legends).
Expected: pass or a list of defects. Recorded as **not verified** until you do it.

## R-7 Tenant time-zone change on a real tenant

1. Pick a test tenant with several weeks of rollup history in the zone Z1.
2. Change the reporting time zone to Z2 (a zone with a different UTC offset and, if possible, a different DST rule) through the settings route.
3. A `timezone_changed` rebuild is queued: `SELECT mode, status, error_code FROM report_rollup_runs WHERE tenant_id = '<tenant>' ORDER BY started_at DESC` shows the old live runs of the range as `failed` with `invalid_range` (voided, Part E fix 1) and new `backfill` runs `succeeded`.
4. Read the trends: the flow series covers the rebuilt range in Z2 days; the backlog/severity series show unknown (null, a gap) for every day of the range until the first live run of Z2, then known from that day only. Never a zero for a day without a live run.
5. Compare one past day's `new_count` with a manual count in Z2 local time.
Expected: flow correct in the new zone, state series null then forward-only, voided runs visible.

## R-8 Export file retention from the tick

1. Set `REPORT_EXPORT_RETENTION_DAYS`-equivalent config (or edit `expires_at` of one ready report to the past with psql on a copy) and keep the worker running.
2. Within one tick (an hour; restart the worker to run one at once) the report turns `expired` and its file under `ARTIFACT_STORE_ROOT/reports/<tenant>/` is gone, while a live report's file stays. The download answers 410.
Expected: expired file removed by the tick even if the tenant never exports again.

## Outcome log

| Gate | Date | Result | Notes |
|---|---|---|---|
| R-1 | | | |
| R-2 | | | |
| R-3 | | | |
| R-4 | | | |
| R-5 | | | |
| R-6 | | | |
| R-7 | | | |
| R-8 | | | |
