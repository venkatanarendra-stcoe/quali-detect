# Screens: reporting and dashboards (T-06, T-20, T-21, T-39 extended; T-46 to T-51 new)

Status: **Draft for owner review (2026-11-26)** with `SPEC.md` of this module. Nothing is built. Identifiers, routes and the existing prompts come from `docs/TENANT_APP_WIREFRAME_SPEC.md` (inventory rows T-06, T-20, T-21, T-39); tokens from `docs/design/DESIGN_SYSTEM.md`; rules from `docs/design/UX_GUIDELINES.md`. Stitch generation is suspended (STITCH_WORKFLOW), so the prompts below are kept for when it resumes and for developers as a written brief.

## Decisions applied (all **Recommended** until ruled; see SPEC 17)

| Id | Effect on the screens |
|---|---|
| SPEC D-1 | Trend charts read daily rollups and show "data as of"; posture tiles are live |
| SPEC D-2 | The page is `workspace.view` (unchanged nav); each tile needs its own section key and is hidden without it; no new sidebar items |
| SPEC D-3 | Exports are asynchronous, redacted by construction, downloaded through the API (no link to copy), scheduling is **not shown** |
| SPEC D-4 | 60-second polling plus invalidation by the existing `finding.changed` hint; Refresh icon |
| SPEC D-5 | One tenant reporting time zone; "Recomputing" state after a change; 7, 30, 90 days and custom |
| SPEC C-1 | Severity charts use `--sev-*` tokens, not the brief's hex values |
| SPEC O-1 | No security posture score tile in v1 |

## 1. Common rules

- **Feature folder** `apps/tenant-web/src/features/reporting/` (`components/ pages/ hooks/ services/ schemas/ stores/ constants/ index.js`). TanStack Query owns the data (keys start with tenant, workspace, `reporting`); Zustand only UI state (chart or table view, toggled series); URL carries `period`, `from`, `to`, `sev`, `view`, `asOf`.
- **Permissions** from the central engine and the section key; an unavailable section is hidden (no placeholder); a visible workspace without the key never renders a number. No role names in UI code. Another tenant's or a hidden workspace shows the standard 404 page.
- **Every data view** has: loading (skeleton shaped like the chart), empty ("No findings yet. Run a scan." with the next step), empty-for-period ("No activity in this period" with the range and a link to widen it), error (message, correlation id, Retry), no-permission, **partial** ("Some sections are not available to you"), **stale** (a chip when a rollup is over two hours late) and **recomputing** (rollups rebuilding after a time-zone change).
- **Data as of:** each card footer reads "Live · updated 14:02" or "Daily rollup · as of 13:00 (Europe/Berlin)"; hover shows the exact instant and the source. A zero is never drawn for a day without data (the axis shows a gap marker and the tooltip says "no data").
- **Charts (Recharts):** severity series in the fixed order Critical to Info with `--sev-*` fills plus a pattern or direct label; other series `--chart-1` (the selected accent, one primary series per chart) to `--chart-4`; gridlines `--chart-grid`; axes `--subtle-foreground`; tabular numerals; no 3D, no gradients; a **Chart / Table** toggle on every chart and a one-sentence summary above it ("Open findings fell from 142 to 128 over 30 days; critical rose by 1.") as the text alternative; keyboard focus moves point by point; tooltips are also reachable by focus.
- **Mint and accent:** only the active navigation item, focus rings, the page's one primary action ("Generate report") and the one primary chart series; never a severity or status; below the 5 percent rule.
- **Severity** = filled tint pill with icon and label (`SeverityBadge`); **status** and **SLA** chips as in the Findings screens (`StatusBadge`, SLA chip: On track, Due soon, Breached; the 25 percent rule is the server's).
- **Drill-down:** a clickable mark (a bar, a segment, a KPI) **filters and opens the Findings list** with the same filters in the URL (`/workspaces/:id/findings?severity=critical&status=...`); the tile count must equal the list count (SPEC 5 rule 2). A user without `finding.view` sees the tile as plain text.
- **Untrusted text** (repository, pipeline and rule names, titles in the oldest-findings list) as escaped plain text; identifiers in mono; no Markdown or HTML.
- **Period control** (one shared component): segmented 7 / 30 / 90 days and "Custom" (two native date inputs, From and To, the app keeps date inputs native until an accessible picker exists, UX); the control shows the time zone name; ranges longer than 400 days are refused inline; a helper line states "30 days = the last 30 days including today (so far)".
- **Density and themes:** dark and light tokens, compact density preference honoured; tables inside cards scroll internally (max 320 px) as in T-21.
- **Realtime and polling:** poll every 60 s while the tab is visible, refetch on focus, debounce hint invalidations by 5 s; a manual Refresh icon always works; no data is kept in local storage.
- **Print:** the dashboard has a print stylesheet (hides controls, expands tables) as a fallback for people who do not need a generated file; it is not the PDF export.

## 2. Alignment with the wireframe (T-20, T-21, T-06, T-39)

| Wireframe item | Treatment here | Metric |
|---|---|---|
| T-20 KPI "Security posture score 72/100 with trend" | **Omitted** in v1 (C-4, O-1); the KPI row shows the components instead | — |
| T-20 "Open findings 128" | kept | P-1 |
| T-20 "Critical 6" | kept (open critical) | P-2 |
| T-20 "Mean time to remediate 9.4 days" | **median** primary with p90 below; mean in the tooltip (C-3) | R-1 |
| T-20 "SLA breaches 3" | kept | R-5 |
| T-20 "Pipelines healthy 11/12" | kept | P-10 |
| T-20 "Findings by severity" bar chart, click filters | kept; the click sets `sev` in the URL | P-2 |
| T-20 "Finding lifecycle" stacked bar (New, In review, Awaiting approval, Assigned, Fixed-pending verification, Verified fixed, Accepted risk) | kept as the **lifecycle groups** of SPEC 5 rule 3 (seven segments) | P-4 |
| T-20 "Execution trend" line chart (succeeded, failed per day) | kept, plus partial and timed out | S-1 |
| T-20 "Team workload" bar chart by assignee | shown only to `finding.assign` holders (O-6) | B-6 |
| T-20 "Connection health (GitHub, Jira)" | **repository connection state** only (O-5); no Jira | S-4 |
| T-20 "SLA status" progress bars | kept | R-5 |
| T-20 filters: period, severity (bar click), Refresh, Chart or Table toggle; URL `period`, `sev`, `view`; **no workspace filter (Confirmed)** | kept exactly; `from`, `to`, `asOf` added | — |
| T-21 table stack (Findings, Pipelines, Repositories, Workload and SLA, Activity) | kept; "Activity" stays the workspace activity feed (not a reporting metric); each table is a drill-down, not a new data source | B-2, B-3, B-6 |
| T-06 KPI row: accessible workspaces, open criticals, executions 7d, SLA breaches | kept (open criticals and SLA breaches summed over accessible workspaces); the period select feeds the executions KPI | B-1 |
| T-06 workspace cards with a mini severity bar, counts, last execution status, "Open dashboard" | kept; the card also shows the SLA-breached count | B-1 |
| T-06 "Recent activity" | unchanged (not a reporting metric) | — |
| T-39 template cards and Generated reports table | kept; two cards added (Detection quality, Point-in-time snapshot); **Audit evidence pack deferred**; format JSON dropped for v1; **Schedule report is not rendered** (RPT-018); the "signed link, expires in 24h" becomes "Download, available for 24 hours after you request it" (SPEC D-3) | SPEC 7.3 |

## 3. Screen inventory

| Id | Screen | Route | Gate | Status |
|---|---|---|---|---|
| T-06 | Organization Overview (extended) | `/overview` | `dashboard.view` (tenant) | Confirmed screen, new content Recommended |
| T-20 | Workspace Dashboard, chart view (extended) | `/workspaces/:workspaceId/dashboard` | `workspace.view`, tiles by section key | Confirmed screen, new content Recommended |
| T-21 | Workspace Dashboard, table view (extended) | `?view=table` | same | same |
| T-39 | Reports (extended) | `/workspaces/:workspaceId/reports` | `report.view` | Planned screen, content Recommended |
| T-46 | Findings trends | `/workspaces/:workspaceId/dashboard/trends` | `finding.view` | Recommended |
| T-47 | Remediation and SLA performance | `/workspaces/:workspaceId/dashboard/remediation` | `finding.view` | Recommended |
| T-48 | Scan activity and coverage | `/workspaces/:workspaceId/dashboard/scan-activity` | `execution.view` | Recommended |
| T-49 | Detection quality (false positives and advisories) | `/workspaces/:workspaceId/dashboard/quality` | `security_review.view` | Recommended |
| T-50 | Generate report (dialog) | dialog on T-39 | `report.export` | Recommended |
| T-51 | Report details (sheet) | sheet on T-39 | `report.view` | Recommended |

The four analysis screens (T-46 to T-49) are reached from "View details" on the dashboard tiles; each shows a small breadcrumb row ("Dashboard / Trends") with links to the other three. They are **not** sidebar items (SPEC D-2), and T-39 has no tab strip for them. `implemented` flips to `true` for the `reports` item only.

## 4. Screens

### T-06 Organization Overview (extended)

**Route** `/overview`. **Gate** `dashboard.view` at tenant scope (Admin only by default, decision 30). **Data** `GET /reporting/overview`.

- **Header:** title, the period select (7, 30, 90, custom), Refresh, "Updated" footer.
- **KPI row (4):** Workspaces (accessible), Open critical findings, Executions in the period (with success rate beneath), SLA breaches. Critical and breaches use severity and status tokens with icon and text.
- **Section "Your workspaces":** 3-column grid of cards; each card: name, description, role chip, a severity bar (Critical to Info counts, labelled), open total, SLA breached, repositories and pipelines counts, last execution status chip, "Open dashboard". Cards sort by open critical then breached; a workspace the person cannot see is **absent**.
- **Section "Top risky repositories"** (B-4 across accessible workspaces): table of 10: repository, workspace, risk points (tooltip with the formula), open critical, open high, breached, last scan. Row opens the repository's findings.
- **Section "Findings over time":** one stacked area chart, tenant-wide open by severity per day, with a Chart/Table toggle.
- **Right column:** "Recent activity" (unchanged).
- **States:** loading skeleton; empty tenant ("No workspaces yet" with Create workspace if permitted); partial (workspaces where the person has no `finding.view` show counts of repositories only and a muted "No findings access"); stale chip; error.
- **Not shown:** per-person data; anything from a workspace the caller cannot see.

*Stitch prompt:* "Update the Organization Overview in the Organization layout shell: header with title and a period segmented control (7d, 30d, 90d, Custom) and a refresh icon. KPI row of 4 cards (Workspaces, Open Critical in the Critical tint with icon, Executions with a small success-rate line, SLA breaches in the danger status colour with icon). Section 'Your workspaces' 3-column cards with name, role chip, a labelled severity bar, open total, breached count, repo and pipeline counts, last execution status chip and 'Open dashboard'. Section 'Top risky repositories' table of 10 with a 'risk points' column and an info tooltip. Section 'Findings over time' stacked area chart in severity tokens with a Chart/Table toggle. Right sidebar card 'Recent activity'. Footer on each card: 'Live, updated 14:02'. Do not use the accent on any severity element."

### T-20 Workspace Dashboard, chart view

**Route** `/workspaces/:workspaceId/dashboard`. **Gate** page `workspace.view`; tiles by key. **Data** `posture`, `trends`, `sla`, `scan-activity`, `coverage`, `workload`.

- **Header:** title "Dashboard", period select, Chart / Table toggle, Refresh. No workspace filter (Confirmed); switching workspace keeps the period and `view` (wireframe rule).
- **Row 1, KPI cards (6):** Open findings (P-1), Critical (P-2, tint), Median time to remediate (R-1, with p90 line), SLA breaches (R-5), Awaiting your decision or approvals (P-8, only with `approval.view`), Pipelines healthy x of y (P-10). Each card shows the change since the start of the period where it is defined (an arrow icon and words, not only color) and links to its drill-down.
- **Row 2:** "Findings by severity" vertical bars (click filters, sets `sev`) and "Finding lifecycle" stacked horizontal bar of the seven groups.
- **Row 3:** "New vs fixed" combo (T-1: new bars, fixed line in the **accent**, closed-without-fix muted, reopened hatched) with "View trends" (T-46); "Execution trend" line chart (S-1) with "View scan activity" (T-48).
- **Row 4:** "SLA status" three progress bars (On track, Due soon, Breached) with counts and "View remediation" (T-47); "Repository coverage" statement (S-4: "9 of 10 active repositories scanned in 30 days", the unscanned ones listed with the reason); "Team workload" bar chart only for `finding.assign`.
- **Row 5 (optional by key):** "Detection quality" mini card (FP rate with n, advisory agreement) linking to T-49 for `security_review.view`.
- **States:** a section without its key is hidden; a new workspace shows the empty-state card with "Connect a repository" and "Create a pipeline" as appropriate; stale and recomputing chips; error per card (one failing card does not blank the page).
- **A11y:** each chart has a summary sentence and a Table toggle; tiles are buttons with a visible focus ring; the order in the DOM is the reading order.

*Stitch prompt:* the existing T-20 prompt of the wireframe with these changes: remove the posture score card, replace "Mean time to remediate" by "Median time to remediate" with a smaller "p90 21 d" line, add "New vs fixed" combo chart, add a "Repository coverage" card, label every card footer with its data age, keep severity colours as design-system tokens.

### T-21 Workspace Dashboard, table view

**Route** `?view=table`. Same gates and data. Severity toggle chips (on/off, URL `sev`). A stack of cards, each with an internally scrolling table (max height 320 px, sticky header): **Findings** (severity, title, repository, pipeline, status, age, assignee; the oldest open critical and high first; 25 rows, "Open in Findings" for the rest), **Pipelines** (name, repository, last run status, duration, open findings), **Repositories** (name, provider, default branch, pipelines, connection state, last scan, risk points), **Workload and SLA** (assignee, open, due soon, breached; `finding.assign` only), **Activity** (unchanged). Every table has the empty, loading and error states and column headers with scope=col; sort by the keyboard.

### T-39 Reports (extended)

**Route** `/workspaces/:workspaceId/reports`. **Gate** `report.view`; Generate needs `report.export` (the button is hidden without it, with a one-line explanation under the page title for a viewer: "You can see reports that were generated. Ask a lead or manager to generate new ones.").

- **Header:** title "Reports"; no Schedule control in v1.
- **Section "Report templates":** cards (SPEC 7.3): Executive security summary (PDF), Findings by pipeline (CSV, PDF), SLA compliance (CSV, PDF), Remediation performance (PDF, CSV), SBOM inventory (CSV), Detection quality (PDF), Point-in-time snapshot (CSV, PDF). Each card: icon, one-line description, formats as chips, a "What's included" disclosure (and "Not included: code excerpts, comments, AI reasoning"), and **Generate** (opens T-50). The Audit evidence pack card is **not rendered** (deferred).
- **Section "Generated reports":** table: Name, Template, Scope (workspace), Period or as-of day, Format, Generated by (display name), Created, Status chip (Queued, Running, Ready, Failed, Expired), Size, **Download** (Ready only, "available until 14:02 tomorrow"), row action opens T-51; Delete for the requester or `report.export` holders. Filters: template, status, mine. Numbered pagination 25 per page.
- **States:** empty ("No reports yet. Generate one from a template above."), generating rows poll every 5 s, failed rows show the stable reason ("Too large: narrow the period or scope"), expired rows say "Expired. Generate again."
- **Tenant-wide reports:** an Admin sees a scope switch "This workspace | Entire organization" in T-50; the Organization layout has no Reports item in v1 (the Admin generates tenant-wide reports from T-50 opened from the Organization Overview "Export" button).

*Stitch prompt:* the existing T-39 prompt with: seven template cards (no Audit evidence pack), each with format chips and a 'What's included' disclosure, no 'Schedule report' button, the table columns Name, Template, Scope, Period, Format, Generated by, Created, Status, Size, Download, status chips with icons, Download shows an expiry hint.

### T-46 Findings trends

**Route** `/workspaces/:workspaceId/dashboard/trends`. **Gate** `finding.view`. **Data** `trends`, `posture?asOf`.

- **Controls:** period, series toggles (severity, scan type, repository filter), "As of" date picker (RPT-007) which switches the top block to the point-in-time numbers and shows a banner "Showing 30 Sep 2026, end of day (Europe/Berlin)".
- **Charts:** (1) open findings by severity per day (stacked area); (2) new vs fixed vs closed without fix vs reopened per day (grouped bars); (3) **burn-down**: open per day with the optional dashed projection labelled "Estimate: at the last 14 days' pace, zero open on 14 Mar" (hidden when not downward); (4) awaiting verification per day (small multiple).
- **Table toggle** for all four and a "Download CSV of this view" link (opens T-50 prefilled, Point-in-time or Findings by pipeline).
- **States:** insufficient history ("Trends need at least 3 days of data; the backfill is running" with progress when a backfill is active), recomputing, stale.

### T-47 Remediation and SLA performance

**Route** `/workspaces/:workspaceId/dashboard/remediation`. **Gate** `finding.view`. **Data** `remediation`, `sla`, `aging`.

- **KPI row:** median time to remediate (R-1) with p90 and n, time to first decision (R-3), SLA compliance of fixes in the period (R-4, per severity), fixed per week (R-2), reopen rate (R-8).
- **Charts:** time to remediate by severity (box-style range bars: median and p90, not a mean-only bar); SLA status by severity (stacked bars On track, Due soon, Breached); **aging** heat strip by age bucket and severity (counts in cells, never color alone); velocity per week.
- **Table "Oldest open critical and high findings":** title (escaped), repository, pipeline, age, SLA state, link to the finding (10 rows).
- **Note under the KPIs:** "Findings are per pipeline; the same issue in two pipelines counts twice" with the O-4 toggle "Count distinct issues".

### T-48 Scan activity and coverage

**Route** `/workspaces/:workspaceId/dashboard/scan-activity`. **Gate** `execution.view`. **Data** `scan-activity`, `coverage`, `sbom`.

- **KPI row:** executions in the period, success rate (S-2, with the definition on hover), median duration and queue wait (S-3), ingestion-eligible share (S-7).
- **Charts:** executions per day by status (stacked; statuses use status tokens with icons in the legend); duration trend (median and p90 lines); result completeness by scan type (S-6).
- **Coverage block (S-4, S-5):** a statement ("9 of 10 active repositories were scanned in the last 30 days") and the table of repositories **not** covered with the reason chip (`no pipeline`, `pipeline disabled`, `no recent scan`, `last scan partial`, `connection unavailable`), plus per-pipeline enabled scan types as four small icons with text.
- **SBOM block (S-8):** components total, by ecosystem (bar), vulnerable share, trend; "Download SBOM inventory (CSV)" opens T-50.
- **States:** pipelines never run, repositories without pipelines, partial results explained, error.

### T-49 Detection quality (false positives and advisories)

**Route** `/workspaces/:workspaceId/dashboard/quality`. **Gate** `security_review.view`. **Data** `quality`.

- **KPI row:** false-positive rate (Q-1) **with n** (below 20 decisions: "n = 14, too few to rate" and the counts), advisory coverage (Q-3), advisory agreement (Q-4), human override of confident advice (Q-5).
- **Charts:** FP rate by scan type and by month; the **advice vs human decision** matrix as a labelled 3 x 2 grid (advisory likely false positive, likely true positive, uncertain against approved false positive, approved true positive) with counts and the sentence "Advice is not a decision. A disagreement may mean the advice was wrong or the reviewer was."; advisory outcomes by status (Q-6) as an operations strip ("Not configured", "Needs consent", "Failed" with counts).
- **Table "Noisiest rules":** rule id (mono), decisions, FP share, n (n >= 20 only).
- **Never shown:** advisory text, reasoning, rationales, any finding title.
- **Banner** when the advisory agent is off for the tenant: "AI advice is turned off; only human decisions are measured."

### T-50 Generate report (dialog)

**Opened from** T-39 (a card or a "Download CSV of this view" link) and the Organization Overview "Export". **Gate** `report.export`.

- **Fields:** Template (read-only when opened from a card), Format (chips; only the formats the template offers), Scope (This workspace; Entire organization for `dashboard.view` holders), Period (the shared control) **or** As-of day for the point-in-time template, Options (for Findings by pipeline: include assignee names, only for `finding.assign`; severity and status filters).
- **Right panel "What this report contains":** the columns or sections in plain words, an **estimated row count**, and the fixed line "Excluded by design: code excerpts, comments, rationales, AI reasoning, secret previews."
- **Actions:** Cancel, **Generate** (the page's one primary action). On success the dialog closes with a toast "Report queued" and the Generated table shows the row; a 429 or `REPORT_TOO_LARGE` stays in the dialog with the stable message ("Too many rows (212,000). Narrow the period or filters.").
- **Keyboard:** focus trap, Escape closes without losing options, the Generate button disabled with a reason while the estimate loads.

### T-51 Report details (sheet)

**Opened from** a row of T-39. **Gate** `report.view`. Shows template, scope, period, format, who generated it, created, started, finished, duration, size, row count, the SHA-256 (mono, copy), status and, for a failure, the stable code and plain explanation; actions: **Download** (Ready), **Generate again with the same options**, **Delete** (requester or `report.export`). No preview of the content (a preview would be a second render path).

## 5. Behaviour rows to run when built

Loading, empty, empty-for-period, empty tenant, error with correlation id, no-permission and 404 on every screen; a tile without its key is hidden; period change updates URL and data; a bar click filters Findings with equal counts; custom range over 400 days refused inline; stale and recomputing chips; Table toggle on every chart; the keyboard path through each chart; a report generated, polled, downloaded and deleted; a failed generation shows its reason; a hostile repository name or finding title renders as text in tables and in the PDF; the reduced-motion and 200 percent zoom checks; screen-reader and human review recorded as **not verified** until a person does them.
