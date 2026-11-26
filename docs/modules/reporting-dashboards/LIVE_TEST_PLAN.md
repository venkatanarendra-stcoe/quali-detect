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
2. Change the reporting time zone to Z2 (a zone with a different UTC offset and, if possible, a different DST rule) through the screen: sign in as an Administrator, open Organization settings, in the "Reporting" card pick Z2 in the list, press "Save time zone" and confirm. The card shows "Recomputing" and checks again every 5 seconds. Or by route: `PUT /api/v1/reporting/settings` with `{ "reportingTimezone": "<Z2>" }` and an `Idempotency-Key` (needs `tenant_settings.manage`); `GET /api/v1/reporting/settings` shows `recomputing`. The zone must be a name the API's runtime lists (`node -e 'console.log(Intl.supportedValuesOf("timeZone"))'`, plus `UTC`); a legacy spelling such as `Asia/Kolkata` is a 400, use `Asia/Calcutta` if that is what the list holds.
3. Exactly one audit entry `tenant.reporting_timezone_changed` (metadata previous and new zone) exists and ONE `reporting.rollup.requested` message (`reason: timezone_changed`, from the earliest history day to today in Z2) was queued (`SELECT message_id, payload FROM outbox_messages WHERE tenant_id = '<tenant>' AND queue = 'reporting' ORDER BY created_at DESC LIMIT 3;`); saving the same zone again adds neither. A `timezone_changed` rebuild is queued: `SELECT mode, status, error_code FROM report_rollup_runs WHERE tenant_id = '<tenant>' ORDER BY started_at DESC` shows the old live runs of the range as `failed` with `invalid_range` (voided, Part E fix 1) and new `backfill` runs `succeeded`.
4. Read the trends: the flow series covers the rebuilt range in Z2 days; the backlog/severity series show unknown (null, a gap) for every day of the range until the first live run of Z2, then known from that day only. Never a zero for a day without a live run.
5. Compare one past day's `new_count` with a manual count in Z2 local time.
Expected: flow correct in the new zone, state series null then forward-only, voided runs visible; the "Recomputing" state of the card ends (the settings answer `recomputing: false`) once the last backfill batch has succeeded; the trends read after the change are not served from the cache of the old zone (the cache epoch moved).

## R-8 Export file retention from the tick

1. Set `REPORT_EXPORT_RETENTION_DAYS`-equivalent config (or edit `expires_at` of one ready report to the past with psql on a copy) and keep the worker running.
2. Within one tick (an hour; restart the worker to run one at once) the report turns `expired` and its file under `ARTIFACT_STORE_ROOT/reports/<tenant>/` is gone, while a live report's file stays. The download answers 410.
Expected: expired file removed by the tick even if the tenant never exports again.

## Outcome log

Live run of 2026-11-26 on the developer's own stack (dev database, real RabbitMQ and Redis, flag ON, the shared database pool because the reporting logins were not provisioned yet). Numbers were read from the database, the API and the processes of that run.

| Gate | Date | Result | Notes |
|---|---|---|---|
| R-1 | 2026-11-26 | PASS | The first tick queued 3 jobs (incremental, close, first-enablement backfill); the queue `qmentis.reporting` had 0 ready messages and 1 consumer, its dead-letter queue 0; the runs are `succeeded` (incremental, close, 6 backfill batches from the earliest history day 2026-04-04). A restarted worker queued nothing new within the same hour (deterministic message ids). |
| R-2 | 2026-11-26 | PENDING (owner) | The migration could not create the group roles (the migration user lacks CREATEROLE: NOTICE path); an admin runs `provision-reporting-logins.js`, which creates the groups, the grants and the two logins. Until then the API and worker use the shared pool and log a warning. |
| R-3 | 2026-11-26 | PASS, one step not run | A posture read missed (60 ms) then hit (38 ms); the key carries the tenant id; a real transition (a review started on a finding) created the epoch keys (value 1, tenant and workspace) and the next read was a miss with new counts (new 53 to 52, in review 14 to 15). The Redis-down fallback was NOT run live (it would stop the Redis your whole stack uses); it is proven in the suite with a double. |
| R-4 | 2026-11-26 | PASS | A backup was taken first (pg_dump). The backfill ran in 6 succeeded batches; the sum of `new_count` over all days is 497 and the number of creation rows in the finding history is 497. The flow series start 2026-04-04; the severity/state series start with the first live run (forward-only) and the UI says so. |
| R-5 | 2026-11-26 | PARTIAL | Machine part PASS: all nine reporting screens render against the real API in headless Chrome (14 distinct reporting calls, none non-2xx, no failed calls). The human review of the PDFs was NOT done (the 12 generated PDFs are in the scratch folder of the run). |
| R-6 | | NOT DONE | needs a human and a screen reader |
| R-7 | 2026-11-26 | PASS with a GAP (the route gap is CLOSED by `AS_BUILT_TZ.md`; the rerun through the screen is PENDING the owner) | The rebuild voided the old runs (`failed`/`invalid_range`) and wrote new `backfill` runs; totals unchanged (497); per-day counts equal a manual count in the zone. The zone was changed by writing the settings row directly, because **no API route or screen sets the tenant reporting time zone** (the data model and the rebuild exist, SPEC D-5 and RPT-020 were not given a route in any part): it is a gap to build. The test data does not straddle a day boundary, so the DST/boundary proof stays the suite's (RPT-S10). |
| R-8 | 2026-11-26 | PASS | A ready report was set past its expiry and the worker's tick removed the file within seconds, set the row `expired`, and the download answered 410 while a live report still downloaded (200). |
| Exports | 2026-11-26 | PASS | 12 reports (CSV and PDF, 7 template and scope combinations, both workspaces) generated in 1.2 to 2.4 s each; 0 hits for 145 needles (every evidence line, rationale, comment, advisory reasoning, justification and note of the database plus the fake token values) in the CSV text and in the decoded and inflated PDF streams. |
| Concurrency and load | 2026-11-26 | PASS | A burst of 5 export requests gave 202, 202, 429 `REPORT_LIMIT_REACHED`, 202 and a 404 for a workspace the caller cannot see; an idempotent replay returned the same report with `Idempotent-Replayed`; 120 concurrent reads over 4 endpoints: 0 errors, p95 734 ms. |

Defects found by this run and fixed: a close job that ran after its day's lag was recorded as a `close` run although it wrote no state, which made the state series start a day early with zeros drawn as data; it is now recorded as a one-day `backfill` and the tick counts it as done (`RPT-S10` check extended; the `RPT-S10f` setup built the way a live worker builds it).
Found and NOT fixed: no route to set the tenant reporting time zone; the Organization Overview chart "Findings over time" says "No findings yet. Run a scan." when the state series has fewer than two days (wrong wording for "not recorded yet"); `Pipelines healthy` reads "0 of 0" for a workspace whose pipelines never ran.
