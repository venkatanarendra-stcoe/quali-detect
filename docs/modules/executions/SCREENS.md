# Screens: executions and scan orchestration

Status: **Approved (2026-11-16)** with `SPEC.md` of this module (owner approval with additions: T-30 out of scope, themed log panel). Nothing is built. The identifiers, routes and prompts come from `docs/TENANT_APP_WIREFRAME_SPEC.md` (WF §5 inventory, §6 prompts T-27 to T-30, §4 RBAC, §1.3 status colours); built screens are described in `docs/modules/pipelines-triggers/SCREENS.md` (PTS) and `docs/modules/repositories-github/SCREENS.md`. Visual rules: `docs/design/DESIGN_SYSTEM.md` and `UX_GUIDELINES.md` (§14 primitives, "Tenant-web page frames and tables"). Labels as in `SPEC.md`: **Confirmed**, **Recommended**, **Open**. The conflicts of `SPEC.md` section 0 (in particular CF-7, CF-8, CF-9, CF-12) apply here.

## Decisions applied from the owner brief and earlier approvals

| Id | Effect on the screens | Label |
|---|---|---|
| B12 / PTS C6 | No placeholder for a module that does not exist: no Findings tab, no "New findings" column, no Artifacts tab, no Analysis or Finding-normalization stages, no "Run manual scan" button (T-30 is a separate module later) | Confirmed |
| B12 | Cursor pagination with a "Load more" footer; **no total counts** anywhere on these screens | Confirmed |
| PTS C4 | Workspace-nested routes; the wireframe route `/executions/:id` is an alias that redirects | Confirmed (C4), applied here Recommended |
| PTS C3 | Disabled-action tooltips say the user lacks permission to run or cancel executions; the permission key is never shown | Confirmed |
| PT §11 | Execution rows show `PR #214`, never the author login | Confirmed |
| Approval addition (d) | T-30 is not part of this module (section 6 is a pointer). The log viewer is a themed mono panel; the `LogTerminal` extension is withdrawn and the always-dark terminal exception stays `AuditTerminal` (audit log) only | Confirmed (owner, 2026-11-16) |
| Approval, EQ-9 and the rest of `SPEC.md` section 15 | Short id in mono instead of an execution number; all other EQ recommendations apply | Confirmed (owner, 2026-11-16) |
| PT R-8, §5.4.1 | A fork execution shows a "Untrusted fork" badge with the explanation of what that means | Confirmed |

## 1. Common rules (**Confirmed**: WF §4.1, §4.5, UX_GUIDELINES, FRONTEND_ARCHITECTURE)

- Feature folder `apps/tenant-web/src/features/executions/` with `components/ pages/ hooks/ services/ schemas/ stores/ constants/ index.js`. The execution status map, chips and time/identifier helpers that today live in `features/pipelines` (`constants/index.js`, `components/pipeline-bits.jsx`) move to the executions feature and are imported by the pipelines feature (no duplicate). TanStack Query owns server data (query keys start with the tenant, then the workspace id, then `executions`); filters live in the URL; Zustand holds only UI state (the "Follow" toggle, the selected log filters); React Hook Form is not needed (no forms except the cancel/retry confirmations).
- Visibility and enabling come from the central authorization engine through `@qmentisai/shared`; **no role names in UI code**. The `executions` item already exists in `WORKSPACE_NAV_GROUPS` with `execution.view` and `implemented: false`; part L flips it to implemented, the navigation is not redefined.
- Actions the user can never perform are **hidden**; actions they may reasonably request are **disabled with a tooltip naming what is missing** ("You need permission to cancel executions in this workspace"). The backend enforces everything (a stale button still gets a 403/404).
- Every data view has **loading** (skeleton shaped like the content), **empty**, **empty-by-filter** (with "Clear filters"), **error** (retry + correlation id) and **no-permission** states. An execution in another workspace, another tenant or nonexistent is the same **not found** page.
- Free text from users and engines (pipeline names, ref names, rule titles, log messages, engine messages) is rendered as escaped text, never as HTML or markdown. Identifiers (execution id, commit SHA, ref, engine id, config hash) are mono, long ones truncated in the middle with a copy button and the full value in a tooltip. Times are relative with the absolute time in a tooltip and `<time datetime>`.
- **Mint:** only the active navigation item, the focus ring and the page's one primary action. T-28 has no primary action (no mint button); T-29's primary action is **Retry** and only when the execution is retryable and the user may retry; Cancel is a destructive outline button. Status colours are independent of the accent.
- **Status chip** (icon + text, never colour alone; WF §1.3 palette, extended): Queued (slate, `Clock`), Preparing (sky, `Loader`), Running (sky-600, animated `Loader`; the animation stops under `prefers-reduced-motion`), Succeeded (green, `CheckCircle2`), Failed (red, `XCircle`), Partial (amber-600, `CircleAlert`), Cancelled (zinc, `CircleSlash`), **Timed out** (red outline, `Timer`; not in the WF palette, **Recommended**), Blocked (amber outline, `Ban`) and Skipped (neutral, `SkipForward`) as built. A cancel request in progress shows the chip "Running" plus the sub-label "Cancelling" (SPEC CF-1: there is no `cancelling` status).
- No `localStorage` for server data; per-viewer conveniences (column density) go through the existing user preferences only.

## 2. Screen inventory

| ID | Screen | Route (workspace-nested) | Route permission | Data (API of SPEC §8) |
|---|---|---|---|---|
| T-28 | Executions list | `/workspaces/:workspaceId/executions` | `execution.view` | `GET /executions?workspaceId=`, `GET /pipelines?workspaceId=` (filter options), row actions |
| T-29 | Execution detail (live) | `/workspaces/:workspaceId/executions/:executionId` | `execution.view` | `GET /executions/{id}`, `/events`, `/logs`, `POST .../cancel`, `POST .../retry`, Socket.IO room |
| (alias) | `/executions/:executionId` (WF route) | redirects after `GET /executions/{id}`; a 404 stays a 404 | as above | |
| (changed) | T-27 pipeline detail, **Executions** tab | `/workspaces/:workspaceId/pipelines/:pipelineId?tab=executions` | `pipeline.view` (tab content `execution.view`) | `GET /executions?pipelineId=`, `GET /pipelines/{id}/trigger-decisions` |
| (dialog) | Cancel execution | dialog on T-28 rows, T-29, T-27 tab | `execution.cancel` | `POST /executions/{id}/cancel` |
| (dialog) | Retry execution | dialog on the same places | `execution.run` | `POST /executions/{id}/retry` |

## 3. T-28 Executions list

**Purpose:** all executions of the workspace, newest first, with live status. **Frame:** `AppPageLayout scroll={false}`, filter bar (`shrink-0`) above a `QueryTable` (`DataTable height="fill"`), as the Pipelines and Audit lists (UX_GUIDELINES "page frames and tables"). **Header:** title "Executions", description "Every run of every pipeline in this workspace." No header button (no "Run manual scan": T-30 is outside this module; the pipelines' "Run now" stays on the pipeline screens).

**Filter bar (URL state, repeated unchanged on every "Load more" request):**

| Filter | Control | Notes |
|---|---|---|
| Status | `MultiSelect` with the ten statuses; quick preset "Active" (Queued, Preparing, Running) | maps to `status` |
| Pipeline | async `Combobox` (`loadOptions`) over `GET /pipelines?workspaceId=&q=` | maps to `pipelineId`; options only from visible pipelines |
| Trigger | `Combobox`: Push, Pull request, Schedule, Manual | WF's "Webhook" splits into Push and Pull request because that is what the API filters |
| Date range | two native date inputs (From, To; the app keeps date inputs native until an accessible picker exists, UX_GUIDELINES) | `from`, `to` on the requested time, interpreted in the user's time zone and sent as UTC instants; invalid or reversed range shows an inline message |
| Clear all | link; active filters also show as removable chips | |

**Columns** (priority P1 always, P2 at 1280 and above, P3 at 1440 and above; **Confirmed** from WF T-28 where data exists):

| Column | Content | Priority |
|---|---|---|
| Execution | short id (first 8 hex, mono, copy button; SPEC EQ-9) | P1 |
| Pipeline | name (link to T-27) with the repository full name under it in muted mono | P1 |
| Status | chip + reason text for non-success terminal states ("Quota exceeded", "Config invalid", "Queued too long"); Running shows the animated chip; a cancel in progress shows "Cancelling" | P1 |
| Trigger | icon + text: "PR #214", "push to main", "schedule", "manual by Priya N.", "retry of 3f9a2c1e"; fork badge "Untrusted fork" | P2 |
| Tasks | "3/4" with four small segments (icon + text per segment on hover/focus), hidden for `queued`, `blocked`, `skipped` | P2 |
| Started | relative; for queued rows "Requested <time>" | P1 |
| Duration | live-ticking client side while running (from `startedAt`), static after; em dash when not started | P2 |
| Commit | short SHA, mono, copy | P3 |
| (actions) | row menu (kebab, last): View, Cancel, Retry, each shown by state and permission; the row also opens T-29 on click/Enter/Space | P1 |

Wireframe columns **not** shown: "New findings" (Findings module, C6). Sorting: only by requested time (newest first, explicit and visible, header button with `aria-sort`); no other sort exists in the API.

**Pagination:** the footer is "Load more" (`hasMore`/`onLoadMore`), appends rows, **moves focus to the first new row and announces "25 more executions loaded"** in a polite live region; no page numbers, no "of N" anywhere. Page size 25 (limit 25/50/100 is a user choice in the footer menu).

**Row actions by state and permission (default roles in section 7):**

| Action | Shown when | Needs | Without the permission |
|---|---|---|---|
| View | always | `execution.view` | n/a |
| Cancel | `queued`, `preparing`, `running` without a pending cancel | `execution.cancel` | disabled with the tooltip above |
| Retry | `failed`, `timed_out`, `partial`, `cancelled`, `blocked` | `execution.run` | disabled with "You need permission to run pipelines in this workspace" |

**Live behaviour:** the page subscribes to the workspace room (SPEC §9.4). For a visible row, an `execution.changed` hint with a newer `rev` patches the status immediately and refetches that row's page quietly; a hint for an execution not on screen shows a non-modal bar "N new or updated executions, Refresh" (it never inserts rows under the user's cursor or changes the scroll position); at the top of an unfiltered list with no extra pages loaded the first page refetches silently. If the socket is down the list polls every 15 s while any visible row is active and every 60 s otherwise, and the header shows a muted "Live updates paused" text with a retry. The status, never the socket, is the truth.

**States:** loading (8 skeleton rows); empty ("No executions yet. Executions appear here when a pipeline runs." with a link "Go to Pipelines" for `pipeline.view` holders); empty-by-filter ("No executions match these filters." + Clear filters); error (message, correlation id, Retry); unauthorized (route guard shows the no-permission page for a workspace the user can see without `execution.view`; a hidden workspace is not found); rows whose pipeline or repository the user may not see show the execution id and status only.

## 4. T-29 Execution detail (live)

**Frame:** `AppPageLayout scroll={false}` + `ScrollTabs` (header, summary and task cards fixed above, the active tab panel scrolls). Breadcrumb "Executions > 3f9a2c1e".

**Header:**
- Title "Execution" + the short id (mono, copy), the status chip (live) and, under it, "<pipeline link> on <repository, mono> · <ref, mono> · <short SHA, mono, copy>" and the trigger text ("PR #214", "push to main", "schedule", "manual by Priya N." (display name), "retry of <link>").
- Actions (right): **Retry** (primary, mint; visible when the status is retryable; disabled with a reason when the pipeline is deleted/disabled or the user lacks `execution.run`; the reason from a `409` is shown inline), **Cancel** (destructive outline; shown for `queued`, `preparing`, `running`; when a cancel is already requested the button is replaced by the text "Cancelling: running scans stop by 12:03" and is not actionable). At most one mint button on the page.
- Dialogs: **Cancel** — queued: "This execution has not started. Cancelling it returns its scan unit."; running graceful: "Running scans may finish for up to 60 seconds, then they are stopped. Results of finished scans are kept."; running immediate: "Scans are stopped now. Results of finished scans are kept." (the mode and grace come from the execution DTO, not from user input); confirm label "Cancel execution", the default focused control is the dismiss button. **Retry** — "Starts a new execution on the same commit with the same configuration version. It counts toward your scan quota." (shows `QUOTA_EXCEEDED` / `ENTITLEMENT_REQUIRED` inline; on success navigates to the new execution). Both send an `Idempotency-Key`.

**Notices (only when true, plain text with an icon, not a banner colour alone):**
- not resolution-eligible (`resolutionEligible = false`): "Incremental scan. Findings that are absent from this run are not marked fixed." for incremental; "This run did not complete a full scan. It cannot mark findings fixed." for `partial`, `failed`, `timed_out`, `cancelled`; for forks additionally "Scanned without credentials. Findings from this run are not auto-assigned." (WF T-29 notice; PT §5.4.1);
- `trust = untrusted_fork`: badge "Untrusted fork" beside the chip with the tooltip text above.

**Stage timeline (horizontal ordered list, `aria-current="step"`):** Queued -> Preparing -> Scans -> Completed. Each completed stage shows its time (from `requestedAt`, `claimedAt`, `startedAt`, `finishedAt`); the last stage's label is the outcome ("Succeeded", "Failed", "Partial", "Cancelled", "Timed out"). The wireframe stages "Repository analysis", "Scan decisioning" and "Finding normalization" are **not shown** (Analysis and Findings modules, C6). Below 1280 px the list scrolls sideways and keeps the current stage in view.

**Facts card:** trigger, requested by (manual/retry only), scan kind and its reason in words ("Full: first run for this pipeline"), configuration version + short hash (mono), requested / started / finished / duration, the deadline while active ("Stops by 14:02"), retry-of link, queue-wait. No SHA of the base unless a pull request (then `base ref` and `PR #n`).

**Scan task cards** (one per enabled scan type, order SBOM, SCA, SAST, Secrets; in a responsive grid: 2 columns at 1280, 4 at 1440; each is an expandable `button`/region with `aria-expanded`):
- title (SCA, SBOM, SAST, Secrets), status chip, engine id/profile (mono), "Attempt 2 of 2" when retried, duration;
- while running: an **indeterminate** progress bar with the text "Running"; **no percentage is shown, because the API provides none** (the wireframe's "64%" is not reproduced);
- when finished: result summary: item count and severity chips (Critical, High, Medium, Low, Info with the severity tokens, icon + text), a "Truncated" badge and the text "Partial results" for an incomplete result;
- expanded: attempts (number, outcome, error class in words, duration), the stable reason text for failed/timed-out/cancelled tasks, and "View log" which sets the Logs tab task filter. No findings list or link (Findings module, C6).

**Tabs:** **Logs** (default), **Events**. Findings and Artifacts are not rendered (C6; the artifact store does not exist). Deep link `?tab=logs|events&task=<id>`.

**Logs tab (decided: SPEC CF-9 / EQ-10 option A):** a bordered, scrollable mono panel that **follows the app theme** (light or dark, existing neutral tokens; **no always-dark panel**: that is reserved for `AuditTerminal`). Line = time (mono), level (icon + text, `error`/`warn` emphasised), source/task tag, message (escaped, wraps, mono because it is terminal output, SPEC rule on mono). Controls: task filter and level filter (`Combobox`), a **Follow** toggle button (`aria-pressed`, default on while the execution is active; scrolling up turns it off and shows "Jump to latest"), "Load earlier" (a plain button at the top; a forward/desc cursor from `GET .../logs?order=desc` loads the newest 200 lines first, then earlier ones on request, then live lines append through `afterSeq`), and a "Log truncated at 20,000 lines" note when the API says so. Redacted values show as `[REDACTED]`. The panel has `role="log"`, `aria-live="off"` (log lines are never announced), `tabindex="0"` and an accessible name; the End key jumps to the latest line. Empty: "No log lines yet." (queued/preparing) or "No log lines were recorded."; loading skeleton lines; error with Retry; unauthorized is the page's no-permission state.

**No `LogTerminal`.** The owner withdrew that extension: the Logs tab is always the themed mono panel above, and the always-dark terminal exception of `DESIGN_SYSTEM.md` applies to the audit log (`AuditTerminal`) only.

**Events tab:** a `DataTable` of the status history (`GET .../events`): time, transition as two chips ("Queued -> Preparing"), reason in words, actor ("System" or the user's display name), cursor "Load more". Recovery rows read "Resumed after a worker restart".

**Live behaviour:** on mount the page subscribes to the execution room and unsubscribes on leave; a hint with `rev` greater than the cached one refetches the detail (and events if open); `task.changed` refetches the detail; `log.appended` appends via `afterSeq` only when Follow is on or the Logs tab is open; hints with an older `rev` are ignored. A small text indicator near the status shows "Live" (icon + text) or "Reconnecting, last update 12:03" (the page falls back to polling: 5 s while active, none when terminal). On a terminal status the page does a final full refetch and stops live work. **Accessibility:** a visually hidden polite live region announces status changes only ("Execution status: Running", "Execution finished: Partial"), throttled to one per 2 s; it never announces log lines.

**States:** loading (header + card skeletons); error (retry + correlation id); not found (same page for hidden/other-tenant/nonexistent); no-permission (workspace visible without `execution.view`); deleted pipeline (the execution stays readable; Retry disabled "The pipeline was deleted"); a `blocked` or `skipped` execution shows no tasks and the reason sentence in place of the timeline.

## 5. T-27 Pipeline detail: how the Executions tab changes

Built today (PTS §6, `features/pipelines/components/executions-tab.jsx`): two parts, **Requests** (minimal offset list from `GET /pipelines/{id}/executions`, Cancel only for `queued` rows) and **Skipped events** (`GET /pipelines/{id}/trigger-decisions`).

| # | Change | Rule |
|---|---|---|
| 1 | **Requests** becomes **Executions**: the same table component as T-28 filtered by `pipelineId` (columns Status with reason, Trigger, Ref, Commit, Scan kind + fork badge, Tasks, Duration, Requested), from `GET /executions?pipelineId=` with cursor "Load more" and **no totals**; the status filter stays; row click opens T-29 | Replaces the offset query; the old route stays in the API until the tab ships (SPEC CF-11) |
| 2 | Row actions: Cancel for `queued`, `preparing`, `running` (`execution.cancel`), Retry for retryable terminal rows (`execution.run`), both through the shared dialogs | disabled with reasons as in T-28 |
| 3 | Footer link **View all executions** to T-28 with `pipelineId` preselected | previously hidden "until the route is implemented" (PTS §2); shown once part L ships |
| 4 | Live updates through the workspace room (patch the visible rows; same "Refresh" bar rule as T-28) | |
| 5 | **Skipped events** section is unchanged | |
| 6 | Status chips on the pipeline's other places (T-25 "Last run", T-24 tab "Last request", T-27 Overview "Last request") gain Preparing, Running, Partial and Timed out through the shared map; the T-25 column header stays "Last run" | no layout change |
| 7 | Tab hidden for a role without `execution.view` (none of the seven default roles; custom roles) shows the no-permission state; the deleted-pipeline read-only view keeps listing executions | |

## 6. T-30 Manual scan request: not in this module

T-30 (manual DAST / Asset Discovery scan) is out of the executions module by the approval (SPEC CF-7, EQ-8): it will be specified in a separate manual-scan module later. Nothing is rendered or reserved here (no button, menu item or placeholder).

## 7. Permission-aware actions by default role (workspace scope)

Legend: **E** enabled, **D** visible but disabled with a reason, **H** hidden, **R** read only.

| Role | T-28 / T-29 view, logs, events | Cancel | Retry | Live updates |
|---|---|---|---|---|
| Admin, Manager, Lead, Dev Lead | E | E | E | E |
| Security Analyst | R | D | D | E |
| Developer | R | D | D | E |
| Viewer | R | D | D | E |

A custom role without `execution.view` gets the no-permission state on the routes and the Executions item is hidden from navigation by the central engine.

## 8. Keyboard and accessibility (checked at implementation)

- Tables: rows are focusable and activate with Enter/Space (the shared `DataTable` behaviour), inner links and the row menu keep working; clicks bubbling from portaled menus/dialogs do not open the row.
- Dialogs: focus trapped, Escape closes without acting, focus returns to the control that opened it; the destructive confirm is not the default focus.
- "Load more" is a real button; focus moves to the first new row and a polite message announces the count.
- Stage timeline and task cards: an ordered list and `aria-expanded` buttons; status text and icon are always present; the Running animation respects `prefers-reduced-motion`.
- Logs panel: `role="log"`, not live-announced, keyboard scrollable, Follow is a toggle button with `aria-pressed`.
- Tab order T-29: breadcrumb, header actions, timeline (not focusable), task cards, tab list, active panel. Colour contrast follows the existing tokens (status chips use the severity/status tokens, never the accent).
- No hover-only information: tooltips repeat text that is available on focus.

## 9. Responsive behaviour (desktop app; checked at 1280 and 1440)

| Width | T-28 | T-29 | Tab in T-27 |
|---|---|---|---|
| 1440 | all columns (P1 to P3); filter bar on one row | task cards in 4 columns, facts card beside the timeline | same columns as T-28 minus Pipeline |
| 1280 | Commit column hidden; filter bar wraps to two rows with "More filters" holding Date range; the table keeps horizontal scroll inside its container, not the page | task cards in 2 columns; facts card below the timeline; timeline scrolls sideways if needed | Commit and Scan kind merge into one cell |
| below 1280 | not targeted by this module (the app shell rules apply) | | |

No horizontal page scroll at either width; the table scrolls inside its own region.

## 10. Verification matrix (to be run by hand after implementation; nothing is claimed)

Unchecked until the screens exist: all seven default roles on T-28, T-29 and the tab; each status chip and its reason text; queued/preparing/running/terminal cancel dialogs (both cancellation modes); retry success, quota error, deleted pipeline; fork execution notice and badge; incremental notice; filter URL round trip and Load more with filters; live update with the socket up, down and reconnecting; reduced motion; keyboard-only run of cancel and retry; screen reader announcement of status changes; 1280 and 1440 layouts; not-found and no-permission pages for a hidden workspace, another tenant and a role without the key; the old `/executions/:id` alias; the pipeline tab's "View all executions" link.
