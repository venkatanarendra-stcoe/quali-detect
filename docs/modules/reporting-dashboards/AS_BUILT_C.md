# Reporting and Dashboards, Part C (exports: CSV and PDF): as built

**Built:** 2026-11-26 on `16486ff` (a worktree branch, not pushed). **Scope:** `SPEC.md` 7.3, 7.4, 9 (export endpoints), 10, 12, 16.2 (`RPT-S05` to `RPT-S08`, `RPT-S12`) with the owner rulings of 0.1 (CSV cap 250,000 rows, 3 concurrent jobs per tenant, 20 per user per hour, 30-day file retention, authenticated download only, pdfkit) and ADR-015. Everything is OFF behind `REPORTING_ENABLED=false`. **Not verified here:** how a PDF looks to a person beyond an engineer's glance at rendered pages (structure and text were inspected by tool; no accessibility, screen-reader or print review), a production object store, the broker delivery of `reporting.export.requested` (the outbox ROW is what is checked), the live run of the reporting worker against RabbitMQ.

## 1. Files (Part C owns only these)

| Area | Files |
|---|---|
| `packages/db/src/reporting/exports/` | `index.js` (the two frozen builders), `api-methods.js` (`createExport`, `countActiveExports`, `countExportsByUserSince`, `getExport`, `listExports`, `softDeleteExport`), `worker-methods.js` (`claimExport`, `getExportForWorker`, `countExportRows`, `readExportPage`, `completeExport`, `failExport`, `expireExports`), `datasets.js` (the SQL of every template, views only), `mappers.js` |
| `apps/workers/src/reporting/export/` | `index.js` (`createExportHandler`), `handler.js`, `object-store.js`, `csv-writer.js`, `pdf-kit.js` (pdfkit page template, tables, vector charts), `templates.js` (CSV records and PDF sections of the seven v1 templates), `retention.js` |
| `apps/api/src/modules/reporting/` | `routes/export.routes.js`, `export-authorization.js`, `export-object-reader.js`, `controllers/export.js`, `services/export.js`, `mappers/export.js`, `schemas/export.js`, `repositories/export.js` |
| Suite | `apps/api/test/security/helpers/reporting/reporting-c-checks.js` (16 checks) and the `C` line of `expected.js` |

## 2. API (all under `REPORTING_ENABLED`; off answers the identical 404 after authentication)

| Route | Gate | Behaviour |
|---|---|---|
| `POST /reporting/reports` | `report.export` in the body's workspace; no `workspaceId` = tenant-wide: `dashboard.view` AND `report.export` in EVERY workspace of the tenant (403 otherwise) | `Idempotency-Key` REQUIRED (a `headers` schema, 400 without it; the kit middleware replays). Frozen `createReportBodySchema`. Resolves the period with the shared helpers in the tenant time zone and STORES `from`/`to` days (a preset becomes a range); an as-of day in the future is `REPORT_PERIOD_INVALID`, before the first history row of the scope `REPORT_AS_OF_UNAVAILABLE` (409). CSV: the row count is computed first (the worker's own `countExportRows`, on the READ role) and a request over 250,000 is `REPORT_TOO_LARGE` (422), never truncated; a count that hits the read role's 5 s timeout is also `REPORT_TOO_LARGE` (`estimate_timeout`). In ONE transaction under a per-tenant advisory lock: at most 3 queued-or-running exports per tenant and 20 requests per user per hour (`REPORT_LIMIT_REACHED` 429, `details.reason` `tenant_concurrent` or `user_hourly`), the `report_exports` row, the outbox message `reporting.export.requested` (payload `{ reportId }` only, message id `reporting-export-<id>`) and the `report.generated` audit entry. 202 `{ reportId }`. `params` holds only validated flags: `distinctIssues` and `includeAssignee` (the requester's `finding.assign`, decided here because the worker cannot evaluate permissions) |
| `GET /reporting/reports?workspaceId=` | `report.view` in the workspace; without `workspaceId` the tenant-wide reports for a `dashboard.view` holder (403 otherwise) | signed keyset cursor (newest first), `canDownload` per caller |
| `GET /reporting/reports/{id}` | `report.view` in the report's workspace (a hidden workspace, another tenant, a deleted or unknown report: the identical 404; a tenant-wide report needs `dashboard.view`, else 404) | status DTO (`reportRunDtoSchema`); never the object key, hash or params |
| `GET /reporting/reports/{id}/download` | the same gate, then the requester OR a `report.export` holder (403), status `ready` (409 `REPORT_NOT_READY`), not expired (410 `REPORT_EXPIRED`, also when the file is gone), size equals the recorded bytes | authenticated stream, `Content-Disposition: attachment` with a SERVER-built filename `qmentisai-<template>-<yyyymmdd>-<8 id chars>.<ext>`, `Content-Type` from the format, `Cache-Control: no-store`, `X-Content-Type-Options: nosniff`, audit `report.downloaded` before the first byte |
| `DELETE /reporting/reports/{id}` | the same gate, then the requester or a `report.export` holder | soft delete; 409 while queued or running; audit `report.deleted`; the worker's retention pass removes the file |

Audit metadata keys are only `template`, `format`, `scope`, `periodFrom`, `periodTo`, `asOfDay`, `estimatedRows`, `bytes`, `rowCount` (ids, enums, days, counts). The audit of a generation is written at REQUEST time (the worker's database role cannot write `audit_logs`); a failed or finished run is visible in the row (`status`, `errorCode`).

## 3. Worker

`createExportHandler` (returns null, so the dispatcher dead-letters, when `ARTIFACT_STORE_ROOT` is not configured): loads the row BY the envelope's tenant AND the report id (a payload tenant that differs is a `NonRetryableError`; the contract schema is already strict), `claimExport` (atomic `queued` to `running`; a replay or a deleted row does nothing; a `running` row older than 15 minutes seen on a redelivery is failed `timeout`), checks the cap with `countExportRows` BEFORE any file exists, builds the file from the datasets a page at a time (memory bounded by the page), stores it, records bytes and SHA-256, `completeExport` (the file is removed when the run is no longer `running`). Failure codes are stable and the only thing stored or logged: `too_large`, `timeout` (15 minute deadline, statement timeout), `source_unavailable` (connection errors), `internal`. After each job the handler runs the bounded retention pass.

**Retention.** `expireReportFiles` (`retention.js`) marks `ready` rows past `expires_at` (30 days, `config.reporting.exportRetentionDays`) and deleted rows `expired` and removes their files. Part A0 gave Part C no tick (the hourly `startRollupTick` is Part A's), so the function is exported and is also called by the export handler after every job (best effort). A tenant that never exports again keeps its expired files until a tick calls the function; the download route answers 410 regardless. **Lead:** call `expireReportFiles` from the rollup tick once an hour.

## 4. The artifact store, reused

The Executions artifact store (`@qmentisai/infra`, `createLocalArtifactStore`) is reused as a DESIGN and partly as code, not as an instance: one validated key, the tenant in every path, no public URL, written under a temporary name then renamed, size-capped and hashed while it streams, root mode 0700 and objects 0600, `ArtifactTooLargeError` (imported). Its key layout (`t/<tenant>/x/<execution>/<name>`) is not the one `report_exports.object_key` demands (`reports/<tenant>/<id>.<format>`, a CHECK), and the shared `parseArtifactRef` requires a name that starts with a letter (a report id may not), so Part C has its own tiny driver with a STRICTER validator: two canonical lower-case UUIDs and a closed list of formats, nothing else forms a key. The worker writes (`object-store.js`), the API reads (`export-object-reader.js`, read only, the same key function); both under `ARTIFACT_STORE_ROOT`, the tree `reports/` next to the Executions tree `t/`. The object name is never taken from `object_key`, a request or a user.

## 5. Datasets and templates (views only)

Every SQL statement reads a `report_*_v` view through the `qm_reporting` role (the suite proves the role cannot read a source table and scans the SQL text for any other table). Definitions follow SPEC 5 and 6 and do not depend on Part A or B: open = the eight open statuses (imported), fixed = `verified_fixed`, the SLA state is the SQL twin of `deriveSlaState` (25 percent), `percentile_cont` for median and p90, the as-of reconstruction uses the status history by `(created_at, rev)` and the decision timeline. Page sizes: 10,000 rows for the findings and the grouped CSVs (a smaller page makes the planner re-scan the whole view for every page: measured 54 s against 14.6 s for the read alone on 250,000 rows).

| Template | CSV | PDF |
|---|---|---|
| executive summary | n/a | KPI tiles, open by severity bars, burn-down (stacked area of the open lifecycle groups per day, rebuilt from the history), top 5 risky repositories with the printed formula, SLA closed and open, scan coverage statement |
| findings by pipeline | one row per finding (all statuses), 14 columns, `Assignee` only for a `finding.assign` requester | open by severity, by pipeline (first 500) |
| SLA compliance | repository x severity x SLA state; open rows carry `open_count`, one `closed` row per repository and severity carries `fixed_in_period` and `fixed_within_sla` | closed, open (stacked bars and table), breached list (100) |
| remediation performance | severity x scan type: count, median, p90, mean days | time to remediate (overall and per severity, reopened-then-fixed), time to first decision, verification lag, weekly velocity and reopen rate |
| SBOM inventory | distinct component rows of the latest SBOM of each pipeline, `vulnerable` = an open SCA finding on the same purl | n/a |
| detection quality | n/a | FP rate (n under 20 is "too few to rate"), noisiest rules (n at least 20), advice versus human decision, override of a confident advisory (confidence 80 or more: an ASSUMPTION, SPEC fixes no band), advisory coverage |
| point-in-time snapshot | repository x scan type x severity open counts at the end of the day | posture by severity, type, status and repository |

**Writers.** CSV: RFC 4180, CRLF, UTF-8, header row from the catalogue, no column outside the template, every cell through `csvSafeCell`, text cells also through `redactCredentialShapes`, streaming in 64 KiB chunks; a BOM only when `params.bom` is true, which no API option can set (the frozen body schema has no such option: see section 8). PDF: pdfkit only, A4, built-in fonts (Helvetica, Helvetica-Bold, Courier), no image, no font file, no link, no annotation, metadata title `QmentisAI <template> report` with no author, header, footer with the page number and the exclusion notice, 40-page cap (`ReportTooLargeError`, `too_large`), tables truncate with an ellipsis and the number of shortened cells is printed, all text passes `redactCredentialShapes` and is mapped to the Latin-1 range (anything else becomes `?`). Charts are vectors with the LIGHT-theme tokens: severity fills are the `-fg` variants (`#B3202D #A8440A #7A5800 #1257B5 #47535F`, DESIGN_SYSTEM 2.2 says light-theme charts use them as fills; the brief's "base hex values" are the dark-theme fills), neutral series `#3D4A50 #5E6F78 #8A9AA3 #C7D1D6`, grid `#DDE4E3`; no accent anywhere (the suite checks the file for the mint values); every series also has a hatch pattern and a direct label.

## 6. Redaction

Structural: the worker role reads views that have no evidence, rationale, comment, reasoning, justification, e-mail or secret preview column (A0). Defence in depth: both writers redact credential shapes again. What the canary run (RPT-S05a) found with the suite's fake tokens:

- the DATABASE refuses a credential-shaped `title` and `path` by CHECK (the planted value fell back to a plain canary), and ingestion redacts them first (`redactCredentialShapes`, IN-7): a title or path cannot hold a secret shape. A plain-text title or path DOES appear in the findings export (it is ordinary content; the check asserts it appears, so the export is not vacuous);
- `rule_id` and `rule_name` ACCEPT a credential-shaped value in the database (no CHECK); the CSV and PDF redaction is the only thing between that value and the file (mutation test: removing the CSV cell redaction made RPT-S05a fail with the planted Slack token in the CSV);
- evidence, rationale, comment, reasoning, justification and note never reach a file, a row, an audit entry, a log line or the outbox message.

## 7. Security suite (ADR-008 area 20), 16 checks

`RPT-S05a` canary across 11 template and format files, report rows, audit, logs and outbox (plain, hex, base64, URL-encoded, reversed, and the decoded and inflated PDF content); `S05b` role privileges, SQL table scan and writer redaction; `S06a` CSV injection vectors read back with an independent parser, also end to end; `S06b` hostile strings in a PDF (content-stream operators read with a string-aware tokenizer, no script, URI, launch, embedded file, form, annotation or open action, intact page tree, title without author); `S06c` page cap, built-in fonts only, light-theme colours, no accent; `S07a` key traversal on the store and the reader; `S07b` another tenant (identical 404 for read, download, delete, list and create); `S08a` concurrency (3 of 6 simultaneous requests accepted); `S08b` hourly limit; `S08c` the cap (250,000 accepted, 250,001 refused before writing, the worker fails `too_large` and writes nothing, a PDF is not row capped); `S08d` idempotent replay and the message; `S08e` authenticated download, headers, hash, 403, 409, 410, 404, tenant-wide rule; `S08f` flag off; `S08g` worker safety, claim, replay, unknown template, deleted row, retention; `S08i` the authorization gate; `S12a` audit entries, allow-listed metadata, atomicity. The checks start a SECOND API process with `REPORTING_ENABLED=true` against the suite's disposable database (the suite's own API keeps the module off) and run the worker handler in process as `qm_reporting` through a `SET LOCAL ROLE` proxy.

## 8. Deviations, gaps and notes for the lead

1. **Frozen defects found (not edited, worked around):** (a) the API configuration (`apps/api/src/config/index.js`) has no `ARTIFACT_STORE_ROOT`; the export routes read `process.env.ARTIFACT_STORE_ROOT` directly (absolute path required). Patch: add `ARTIFACT_STORE_ROOT: z.string().optional()` and `config.reporting.artifactStoreRoot`. (b) `createReportBodySchema.options` allows only `distinctIssues`, so the CSV BOM option of SPEC 12 item 3 cannot be requested; the writer supports `params.bom`. Patch: add `bom: z.boolean().optional()` to `options`. (c) `contract:snapshot` records `permission: null` for the five export routes because their gates are composite; add `NAMED_GATES` entries for `gate.create` (`report.export`, tenant-wide: `dashboard.view` plus `report.export` everywhere), `gate.list` and `gate.item` (`report.view`). (d) `REPORTING_ROUTE_SCHEMAS` has no `headers` entry: the `Idempotency-Key` header schema is Part C's.
2. **The tenant-wide scope reading:** `report.export` is a workspace key, so "at tenant scope" is implemented as held in EVERY workspace of the tenant (and the caller must see all of them) together with `dashboard.view`.
3. **`report.generated` is audited when the report is REQUESTED**, with `estimatedRows` for a CSV, not when the file is finished (the worker role cannot write the audit log; ADR-011 `report.generated` and `report.failed` events to the outbox are not emitted by Part C).
4. **Point-in-time severity:** the views carry the effective severity but not the tool severity, so a finding whose severity was changed ONLY AFTER the chosen day cannot be reconstructed; it is counted as `unknown` and the PDF says so. Part A's rollup may supersede this.
5. **Scan coverage statement** reads the scan history only: a repository that never ran a scan, or that has no enabled pipeline, is not part of it (the views carry no repository or pipeline enabled flag); there is no default-branch filter.
6. **PDF scope line** says "one workspace" or "every workspace of the organization": no workspace name is readable from the views.
7. **Pipelines of a tenant-wide report** include every workspace, not the caller's accessible set; the caller must see all workspaces to request one.
8. A download is gated twice: the route needs `report.view` in the report's workspace (a hidden workspace is the identical 404, a visible one without the key 403), then the service needs the requester or a `report.export` holder (403).

## 9. Measurements (this machine; local PostgreSQL 18, one process, the worker connected as a superuser so the role is not what is timed; peak RSS is `process.resourceUsage().maxRSS` of the whole worker process including the Prisma engine)

Generated dataset: 250,000 findings in one workspace (a SQL helper in the scratchpad, triggers off), one history row each; trimmed to the sizes below.

| Case | Rows read | Time | Peak RSS | File |
|---|---|---|---|---|
| CSV, 252,003 rows (over the cap) | count only | 0.11 s | 138 MiB | refused `too_large`, no file |
| CSV findings by pipeline, 250,000 rows | 250,000 | **24.3 s** | 369 MiB | 57.4 MB |
| CSV findings by pipeline, 50,000 rows | 50,000 | **3.6 s** | 232 MiB | 11.5 MB |
| PDF findings by pipeline, 50,000 source rows | 50,000 | 0.5 s | 138 MiB | 9.6 KB |
| PDF executive summary, 50,000 source rows | 50,000 | 2.9 s | 152 MiB | 79 KB |
| PDF point-in-time snapshot, 50,000 source rows | 50,000 | 1.7 s | 135 MiB | 9.9 KB |
| PDF SLA compliance, remediation, detection quality (50,000 findings) | n/a | 0.6 s, 0.35 s, 0.14 s | under 152 MiB | 16 KB, 5 KB, 3.6 KB |
| PDF executive summary at 252,003 source rows | 252,003 | 11.8 s | 139 MiB | 80 KB |

Target of SPEC 14 (a 50,000-row export under 60 s): met by a wide margin. The first CSV run used a 2,000-row page and took 73.2 s for 250,000 rows (199 MiB): the keyset query re-scans the join view for each page, so the page was raised to 10,000. A separate dataset in the live database, a realistic network round trip to a remote PostgreSQL and the production role's statement timeout were not measured.
