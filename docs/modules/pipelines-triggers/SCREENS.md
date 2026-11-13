# Screens: pipelines and triggers

Status: **Approved (2026-11-12)**, **Implemented 2026-11-13** (part F; see section 10 for what was built, the deviations and the verification matrix), companion to `SPEC.md` of this module (decisions applied at approval are listed there). Sections 1 to 9 are the approved specification and are unchanged. The identifiers, routes and prompts come from `docs/TENANT_APP_WIREFRAME_SPEC.md` (WF §5 inventory, §6 prompts T-24 to T-27, §4 RBAC); the existing built screens are described in `docs/modules/repositories-github/SCREENS.md`. Visual rules: `docs/design/DESIGN_SYSTEM.md` and `UX_GUIDELINES.md` (Geist Sans, mono only for identifiers such as repository full names, branch names, SHAs, cron expressions and pipeline keys, Lucide icons, **mint only for the primary action, active navigation and focus**, severity colors independent of the brand and never the only signal, status as an outlined chip with icon and text). Labels as in the SPEC: **Confirmed**, **Confirmed (owner, 2026-11-12)**, **Recommended — default applied**, **Open**.

## Decisions applied at approval (2026-11-12)

| Id | Effect on the screens |
|---|---|
| C4 | Workspace-nested routes (`/workspaces/:workspaceId/pipelines...`) are the routes; the wireframe routes are aliases that redirect |
| C3 | Tooltips say the user lacks permission to run pipelines (key `execution.run`, never shown); `execution.view` exists |
| C6 | Wireframe columns, KPIs and tabs that depend on later modules (last duration, success rate, open findings, KPI cards, history strip, trend, Findings tab, Notifications step) **stay hidden until those modules exist**; no placeholders |
| Q5, Q6 | Fork policy control: "Do not run" (default) / "Run without credentials"; choosing the latter needs `pipeline.manage_fork_policy` (hidden or disabled with a reason without it), asks for confirmation and is audited |
| Q20 | T-27 shows trigger decision rows (policy skips with reason) in a **Skipped events** section; a non-matching branch shows nothing (counters only); quota blocks and denied manual runs appear in Activity (audit) |
| Q11 | Timeout controls show the defaults (30 min execution, 15 min scan task) and the cap (120 min) from `options` |
| R-8 | The wizard offers no command, script, install or build field; a note under Scans says "Scans read manifests and lockfiles; they never install packages or run repository code." |
| Q9 | No path filters on triggers (deferred to the Analysis module) |

## 1. Common rules (**Confirmed**: WF §4.1, §4.5, UX_GUIDELINES, FRONTEND_ARCHITECTURE)

- Feature folder `apps/tenant-web/src/features/pipelines/` with `components/ pages/ hooks/ services/ schemas/ stores/ constants/ index.js`; TanStack Query owns server data (query keys start with the tenant, then the workspace id); Zustand only for wizard UI state that is not in the form; filters, sorting, page and the wizard step live in the URL; forms with React Hook Form and Zod schemas that mirror the API contract; Sonner for toasts.
- Visibility and enabling come from the central authorization engine through `@qmentisai/shared`; **no role names in UI code**. Navigation item `pipelines` already exists in `@qmentisai/shared` (`WORKSPACE_NAV_GROUPS`, permission `pipeline.view`, implemented) and today routes to a placeholder page; the route gets its real page, the navigation is not redefined.
- Actions the user can never perform are **hidden**; actions they may reasonably request are **disabled with a tooltip naming what is missing** ("You need permission to run pipelines in this workspace", not the key, matching AZ Q13's no-key rule for 403 bodies; the tooltip may use the human label). The backend enforces everything.
- Every data view has **loading** (skeleton matching the layout), **empty**, **empty-by-filter** (Clear filters), **error** (with retry and the correlation id) and **no-permission** states; a pipeline in another workspace, another tenant or nonexistent is the same **not found** page. No counts or names the user cannot access.
- Free text from GitHub or users (names, descriptions, branch names, patterns) is rendered as escaped text; identifiers are mono, long ones truncated in the middle with a copy button and the full value in a tooltip; times are relative with the absolute time in a tooltip.
- Primary action per page is the only mint button.

## 2. Screen inventory

| ID | Screen | Route (workspace-nested, **Confirmed (owner, 2026-11-12)**; WF shows `/pipelines/...`) | Route permission | Data (API of SPEC §8) |
|---|---|---|---|---|
| T-24 (changed) | Repository detail, **Pipelines tab** | `/workspaces/:workspaceId/repositories/:repositoryId` (tab state `?tab=pipelines`) | `repository.view` (tab content: `pipeline.view`) | `GET /repositories/{id}`, `GET /repositories/{id}/pipelines` |
| T-25 | Pipelines list | `/workspaces/:workspaceId/pipelines` | `pipeline.view` | `GET /pipelines?workspaceId=`, `PUT/POST` row actions |
| T-26 | Create / edit pipeline (wizard) | `/workspaces/:workspaceId/pipelines/new?repository=:repositoryId` and `/workspaces/:workspaceId/pipelines/:pipelineId/edit` | `pipeline.manage` | `GET /workspaces/{id}/pipelines/options`, `POST /repositories/{id}/pipelines`, `PUT /pipelines/{id}/config`, `PATCH /pipelines/{id}`, `POST /repositories/{id}/pipelines/test-triggers` |
| T-27 | Pipeline detail | `/workspaces/:workspaceId/pipelines/:pipelineId` | `pipeline.view` | `GET /pipelines/{id}`, `/versions`, `/executions`, `/trigger-decisions`, row actions |
| (alias) | `/pipelines/:pipelineId`, `/pipelines/:pipelineId/edit` | redirect to the workspace-nested URL after `GET /pipelines/{id}` (404 stays 404) | as above | |
| (dialog) | Run now | dialog on T-24/T-25/T-27 | `execution.run` | `POST /pipelines/{id}/runs` |
| (dialog) | Test triggers (dry run) | dialog on T-26 Review and T-27 | `pipeline.view` | `POST .../test-triggers` |
| (dialog) | Delete pipeline | typed-name confirmation | `pipeline.delete` | `DELETE /pipelines/{id}` |

Executions list/detail (T-28/T-29), Findings and the manual DAST / Asset Discovery dialog (T-30) belong to later modules. Where this module links to them (the T-27 Executions tab, "View all") the link is hidden until the route is implemented (WF §4.3: `implemented: false` items stay hidden).

## 3. T-24 Repository detail: what changes in the built screen

Built today (`apps/tenant-web/src/features/repositories/pages/repository-detail-page.jsx`): tabs Overview, Branches, Pull requests, Webhooks, Settings; the Overview shows "Pipelines" with `repository.pipelineCount` (always 0, the API mapper hard-codes it); no "Add pipeline", no Pipelines tab (SCREENS of the previous module: "arrive with their modules").

| # | Change | Rule |
|---|---|---|
| 1 | New tab **Pipelines**, placed after Overview (WF order: Overview, Pipelines, Branches, Pull requests, Commits, Webhooks, Settings; Commits remains absent) | Visible with `pipeline.view` (every role); content from `GET /repositories/{id}/pipelines` |
| 2 | Tab content: compact table of the repository's pipelines (name, triggers as chips: `Push main`, `Pull request`, `Schedule 02:00 Europe/Berlin`, `Manual`; scans chips: SCA, SBOM, SAST, Secrets; last request status and time; effective state chip; Enabled toggle; row actions Run now, Edit, Open) and an empty state | Toggle and Edit need `pipeline.manage`; Run now needs `execution.run` (disabled with reason otherwise) |
| 3 | Header action **Add pipeline** (primary, the only mint button; existing Sync now / Enable-Disable / Disconnect stay secondary) opens `/workspaces/:workspaceId/pipelines/new?repository=:id` | Hidden without `pipeline.manage`; **disabled with a reason** when the repository is `unavailable`, `disconnected` or disabled ("Pipelines can be created once the repository is active") or when `pipelines.max` is reached ("Your plan limit of N pipelines is reached", from the 403 `QUOTA_EXCEEDED`) |
| 4 | Overview "Pipelines" links to the tab ("View pipelines"; the number is no longer shown, 2026-11-13 item 4); empty value "0" keeps a link "Add pipeline" for `pipeline.manage` holders | Count comes from the pipelines module through the repository DTO; `null` (hidden) if the caller lacks `pipeline.view` |
| 5 | Banner on `unavailable` / `disconnected` repositories gains one sentence: "Its pipelines are stopped and resume automatically when the repository is active again." (SCM A5 text "their pipelines stop") | Matches the derived effective state, SPEC §5.2 |
| 6 | The T-22 repositories list column "Pipelines" shows the real count | |
| 7 | Disable/Disconnect dialogs keep their existing text; no change | |

States for the tab: loading skeleton rows, empty ("No pipelines on this repository. A pipeline decides what is scanned and when." + Add pipeline for `pipeline.manage`; read-only roles see the sentence only), error with retry, a repository in a hidden workspace is not found (unchanged). Wireframe overview items (languages bar, SBOM card, findings by severity) wait for later modules.

## 4. T-25 Pipelines list

**Purpose:** all pipelines of the workspace. **Header:** title "Pipelines", primary **Create pipeline** (hidden without `pipeline.manage`; opens the wizard with a repository picker).

**Toolbar (URL state):** search by name, Repository filter (only repositories of this workspace), Trigger type filter (Push, Pull request, Schedule, Manual), State filter (Enabled, Disabled, Stopped by repository), "Show deleted" (for `pipeline.view` holders; shows deleted rows labelled "Deleted", read only).

**Table columns (Confirmed from WF T-25 where data exists now):**

| Column | Content | Available now? |
|---|---|---|
| Pipeline | name (link), description under it in muted text | yes |
| Repository | full name, mono | yes |
| Triggers | chips: Push to `main`, Pull request, Schedule `daily 02:00`, Manual (tooltip shows patterns, cron, time zone) | yes |
| Scans | chips SCA, SBOM, SAST, Secrets (enabled ones) | yes |
| Last request | status chip (Queued, Blocked, Skipped, Cancelled) + relative time | yes (minimal; later the execution statuses) |
| State | outlined chip: Enabled, Disabled, Repository unavailable / disconnected / disabled, Workspace archived (text + icon, tooltip with the reason) | yes |
| Enabled | switch | yes (`pipeline.manage`; otherwise read-only) |
| Last duration, Success rate (last 20), Open findings | WF columns | **hidden until the execution and findings modules exist** (§8 difference 2) |
| Row actions | Run now, Edit, Duplicate, Enable/Disable, Delete | per permission |

**Actions per permission:**

| Action | Needs | Without it |
|---|---|---|
| Run now (dialog: ref, scan kind, confirm) | `execution.run`, pipeline enabled, repository active | hidden if the pipeline is deleted; **disabled with reason** for Security Analyst, Developer, Viewer ("You don't have permission to run pipelines in this workspace"), for a disabled pipeline ("Enable the pipeline to run it") and for an inactive repository |
| Edit, Duplicate (opens the wizard prefilled, name suffixed " copy") | `pipeline.manage` | hidden for read-only roles |
| Enable / Disable switch | `pipeline.manage` | read-only switch (disabled with tooltip) |
| Delete (typed name; explains: history and findings are kept, queued requests are cancelled) | `pipeline.delete` | hidden except for Admin and Manager by default; disabled with the reason "Cancel running executions first" when the API answers `has_active_executions` |

**States:** loading (8 skeleton rows), empty ("No pipelines yet. Create the first pipeline to start scanning a repository." + Create pipeline for `pipeline.manage`; "Connect a repository first" with a link when the workspace has no repository and the user holds `repository.connect`), empty-by-filter, error (retry + correlation id), no-permission (explains who to ask; no data), workspace not visible = not found. Pagination and sort in the URL (`sort=name|createdAt|lastRequestedAt`).

## 5. T-26 Create / edit pipeline wizard

Left vertical stepper (WF prompt), URL `?step=basics|triggers|scans|controls|notifications|review`, a right-hand **Pipeline summary** card, unsaved-changes guard, keyboard-accessible stepper. The same wizard edits an existing pipeline: it loads the current version, and saving publishes **version N+1** (the Review step shows "Saving creates version N+1; executions already requested keep version N"). A stale save shows the `version_conflict` message with "Reload the latest version".

| Step | Fields and rules |
|---|---|
| 1 Basics | Repository (select of active, enabled repositories of this workspace visible to the user; locked when editing or when opened from T-24), Name (unique per repository, inline `name_taken` error), Description, "Enable after creating" (checked) |
| 2 Triggers | One card per trigger with an on/off switch: **Push** (branch include/exclude patterns with a live example, tags opt-in with patterns, "scan new branches", "scan force pushes"), **Pull request** (actions checkboxes `opened`, `synchronize`, `reopened`, `ready for review`; target branches; draft PRs: Skip / Run; **Fork pull requests: "Do not run" (default) / "Run without credentials"**, with a helper text: "Fork PRs are untrusted. They never get secrets or integration credentials and cannot mark findings fixed. If GitHub does not say, a PR counts as a fork."), **Schedule** (cron with a human preview and the next 5 fire times, IANA time-zone select with search, missed-run policy, minimum interval hint from `options`), **Manual** (switch). A pattern tester shows which sample branch names match. Choosing "Run without credentials" requires the permission `pipeline.manage_fork_policy` (Admin and Lead by default): without it the option is **disabled with the reason** "You need permission to allow fork pull requests to run" (the control stays visible and shows the current value read-only), and with it a confirmation dialog explains the untrusted-fork contract (no credentials, code archive only, results marked untrusted, not auto-assigned). Setting it back to "Do not run" needs only `pipeline.manage` |
| 3 Scans | Cards for SCA, SBOM, SAST, Secret Scanning with an enable toggle, **engine select (placeholder catalog: "Default engine" only for now)**, profile select (when the catalog offers one) and severity threshold select (Info, Low, Medium, High, Critical, shown with the severity pill, icon plus text). Separate read-only section **"Manual-only scans: DAST and Asset Discovery"** with the note "Run on demand; never triggered automatically" and, for `scan.run_manual` holders, a link to the manual scan flow once T-30 exists (hidden before). Excluded paths (pattern list). A fixed note: "Scans read manifests and lockfiles. They never install packages, run scripts or build your code." |
| 4 Execution controls | Scan mode (Incremental / Full) with helper "Incremental scans never mark findings as fixed. The first run, a changed scan configuration, new branches, force pushes and schedules run a full scan." Timeout (default 30 min, platform maximum 120 min) and Scan task timeout (default 15 min), Concurrency policy (Supersede older, Queue, Skip) with maxQueued where relevant, Cancellation (Graceful / Immediate), **Fail pipeline on** (severity select, New findings only / All findings, engine errors) |
| 5 Notifications | **Hidden** until the notification module exists (WF shows it); the stepper shows 5 steps, numbering is stable in the URL |
| 6 Review | Summary of everything, validation result (field errors link back to their step), a **"Test triggers" button** (dry run: choose a sample push or PR, shows which triggers would run, scan kind and trust; no side effects), a "Change note" field when editing, a diff summary against the current version when editing, and the primary button **Create pipeline** or **Save as version N+1** |

**States:** loading (options and, when editing, the pipeline), error loading (retry), validation errors inline from `VALIDATION_FAILED` details, conflict messages (`name_taken`, `version_conflict`, `repository_not_active`), `QUOTA_EXCEEDED` for `pipelines.max` as an inline banner with the limit, no-permission page for users without `pipeline.manage` (the wizard URL does not render; the nav/actions that lead to it are hidden), not found for a hidden pipeline or workspace. Submit is disabled while pending and sends an `Idempotency-Key`.

## 6. T-27 Pipeline detail

**Header:** name, repository (mono, link), effective-state chip, **Enabled** switch (`pipeline.manage`), buttons **Run now** (secondary; `execution.run`, disabled with reason as in T-25) and **Edit** (primary look only if no other primary on the page; per the mint rule the single primary is **Edit** for managers and **Run now** for roles that can run but not manage, never both), overflow menu with Duplicate, Test triggers, Delete.

**Banner (WF):** "Findings in this pipeline have their own identity and lifecycle, independent of other pipelines." (ADR-004). A second banner appears when the effective state is not running normally ("Stopped: the repository is disconnected. It resumes automatically when the repository is active.").

**Tabs (WF: Overview, Executions, Findings, Configuration, Triggers, Activity; available now vs later):**

| Tab | Content now | Later |
|---|---|---|
| Overview | description, repository, state, current version and hash (short, mono, copy), next scheduled run, counters (requests in 30 days, blocked, skipped by policy in 24 h from the decision rows) | KPI cards (success rate, average duration, open findings), history strip, findings trend (hidden until those modules) |
| Executions | two parts. **Requests:** minimal list of execution requests (status chip, trigger icon and "PR #214" / "push to main" / "schedule" / "by name", ref, commit SHA mono, scan kind, trust badge for forks, time); Cancel for `queued` rows (`execution.cancel`); reason text for Blocked and Skipped. **Skipped events:** list of trigger decision rows (time, trigger, ref or "PR #214", reason such as "Fork pull request, policy is Do not run", "Pull request closed, queued run cancelled" (`cancelled_pr_closed`, owner decision 2026-11-13: not a skip, so it is not counted in "skipped by policy"; the cancelled request itself shows the same text as its reason), "Draft pull request", "Repository disconnected", "Pipeline disabled"), from `GET /pipelines/{id}/trigger-decisions`; **schedule skips appear here too** (owner decision 2026-11-13, SPEC §5.9b, §7.8): the row shows the **slot time** (`scheduleSlot`, in the viewer's time zone with the UTC instant as a tooltip), the **trigger** (key and a schedule icon, "schedule nightly") and the reason ("Repository disconnected", "Repository disabled", "Workspace archived", "Pipeline disabled") instead of a PR number or ref; the list can be filtered by source (`sourceType`: webhook event, schedule slot) and the SCM delivery id is shown only for webhook rows; events that did not match any trigger are not listed | rich list, detail links (T-28/T-29) |
| Findings | **hidden** until the Findings module (tab not rendered, no placeholder page) | |
| Configuration | read-only view of the current version with a version selector and a compare-with-previous diff; "Edit" opens the wizard | |
| Triggers | one card per trigger with its options, enabled switch (`pipeline.manage`; changing it publishes a new version, the dialog says so) and the schedule's next five fire times; "Test triggers" | |
| Activity | audit entries for this pipeline (`pipeline.*` incl. `pipeline.fork_policy_changed`, `execution.manual_requested`, `execution.manual_denied`, `execution.blocked`, `execution.skipped`, `execution.cancelled_pr_closed`) from the audit API, visible with `workspace.view_activity` (otherwise the tab is hidden) | |

**States:** loading skeleton, error with retry and correlation id, not found, no-permission (pipeline visible but a tab's data denied: that tab shows the no-permission state), Deleted pipeline: read-only view with a "Deleted on <date> by <user>" banner and no actions; reachable only through "Show deleted" or a direct link by a user with `pipeline.view`.

## 7. Permission-aware actions by default role (workspace scope)

Legend: **E** = enabled, **D** = visible but disabled with a reason, **H** = hidden, **R** = read only.

| Action / screen | Admin | Manager | Lead | Security Analyst | Dev Lead | Developer | Viewer |
|---|---|---|---|---|---|---|---|
| Nav item Pipelines, T-25, T-27, T-24 tab | E | E | E | R | E | R | R |
| Create pipeline / Add pipeline | E | E | E | H | E | H | H |
| Edit, Duplicate, Enable/Disable switch | E | E | E | H (switch D) | E | H (switch D) | H (switch D) |
| Publish configuration, change triggers | E | E | E | H | E | H | H |
| Set fork policy to "Run without credentials" (`pipeline.manage_fork_policy`; Q6) | E | D | E | H | D | H | H |
| Run now | E | E | E | D | E | D | D |
| Cancel a queued request | E | E | E | H | E | H | H |
| Delete pipeline | E | E | H | H | H | H | H |
| Test triggers (dry run) | E | E | E | E | E | E | E |
| Activity tab | E | E | E | E | E | H | H |

(Fork-policy row: Manager and Dev Lead hold `pipeline.manage` but not `pipeline.manage_fork_policy`, so the option is visible but disabled with a reason; Admin and Lead can set it. Role columns follow AZ §5.4 and `roles.js`; `workspace.view_activity` is held by Admin, Manager, Lead, Security Analyst and Dev Lead in `roles.js`. The UI never tests the role name: it evaluates the keys through the central engine, so a custom role behaves by its keys.)

## 8. Differences from the wireframe (catalog wins on conflicts)

| # | Wireframe | This specification |
|---|---|---|
| 1 | Routes `/pipelines/new`, `/pipelines/:id`, `/pipelines/:id/edit`, T-24 at `/repositories/:id` | Workspace-nested routes like the built repositories screens (aliases redirect); `SPEC §15.2 C4`, Confirmed (owner, 2026-11-12) |
| 2 | T-25 columns last duration, success rate (last 20), open findings; T-27 KPI cards, history strip, trend, Findings tab | Hidden until the execution and findings modules exist (no placeholders, WF §4.3 rule; owner decision C6, 2026-11-12) |
| 3 | T-27 tooltip "You need `pipeline.run`" and `pipeline.manage (Rec.)` | Catalog keys: run is `execution.run`, manage is `pipeline.manage`; `execution.view` exists (C3, `docs/TENANT_APP_WIREFRAME_SPEC.md` amended) |
| 4 | T-26 step 5 Notifications | Hidden until the notification module exists |
| 5 | T-26 step 3 engine select "Built-in, Semgrep, Trivy" | Placeholder catalog (one default engine per scan type); real engines arrive with the engine modules |
| 6 | T-26 step 2 does not mention fork policy, tags, drafts, cron limits, missed runs | Added (SPEC §5.3 to §5.6); fork policy per §5.4.1 |
| 7 | T-25 row action "Duplicate" | Client-side clone through create (`copyFromPipelineId` optional) |
| 8 | T-25/T-27 "Pause" wording in TAD §3.4 | "Disable" (the catalog says enable/disable); effective states are shown separately |
| 9 | T-24 overview content (languages, SBOM, findings) and Commits tab | Not part of this module; only the Pipelines tab and Add pipeline change |
| 10 | T-30 manual scan dialog | Separate module flow; this module only links to it when it exists |

## 9. Verification plan after implementation

A headless-browser pass over all seven seeded roles for T-24 (tab and Add pipeline), T-25, T-26, T-27 and the Run now and Delete dialogs against a disposable stack and the GitHub stub, recorded in this file in the same format as the previous module's verification matrix (which states were exercised, which were not, defects found and fixed). Not part of `pnpm test:security` (ADR-008 forbids UI tests); the API side of the same rules is covered by `PIP-*`.

## 10. As built (Implemented 2026-11-13, part F)

Code: `apps/tenant-web/src/features/pipelines/` (`components/ pages/ hooks/ services/ schemas/ stores/ constants/ index.js`), the T-24 changes in `features/repositories/pages/repository-detail-page.jsx` and `repositories-page.jsx`, `components/ui/switch.jsx` (native `role="switch"`, no new dependency), and `ConfirmDialog` gained `errorText` and `confirmDisabled`. The configuration form validates with `createPipelineConfigSchema(options.limits)` from `@qmentisai/shared`, the same schema as the API (hints only; the API stays authoritative and its `VALIDATION_FAILED` issues are mapped back onto the steps).

**Routes (all inside `WorkspaceScope`, checked in the URL's workspace):** `/workspaces/:id/pipelines` (`pipeline.view`, navigation item `pipelines`), `.../pipelines/new?repository=&copy=` and `.../pipelines/:pipelineId/edit` (`pipeline.manage`; a role without it gets the 403 page), `.../pipelines/:pipelineId` (`pipeline.view`; `?tab=overview|executions|configuration|triggers`). Wizard step in `?step=`. Aliases `/pipelines`, `/pipelines/new`, `/pipelines/:id`, `/pipelines/:id/edit` redirect (the workspace comes from the pipeline or repository after a read; a hidden or missing pipeline stays the same 404 page). T-24 tab in `?tab=pipelines`. Workspace switching keeps the section and the query string.

**Deviations from sections 1 to 9 (the API shapes win):**

| # | Specified | Built | Why |
|---|---|---|---|
| 1 | Trigger chips with patterns and scan chips from the list | Chips by type and key from the list DTO; patterns, cron and scan chips come from the current version, fetched per visible row (`GET .../versions/{n}`, immutable, cached for the session) | The pipeline DTO carries no configuration |
| 2 | Cancel for queued requests (`execution.cancel`) | No cancel control | The API has no cancel route yet (queued requests are cancelled only by deleting the pipeline) |
| 3 | Activity tab (`workspace.view_activity`) | Not rendered | No workspace-scoped audit API; the tenant audit list needs `audit_log.view_all` |
| 4 | Overview counters: requests in 30 days, blocked | Skipped by policy (24 h) and the last request only | The API returns only `counters.skippedByPolicyLast24h` |
| 5 | "Deleted on <date> by <user>" | "Deleted on <date>" | The DTO has `deletedAt` and no deleter |
| 6 | State filter Enabled / Disabled / Stopped by repository | One option per effective state (enabled, disabled, repository disabled / unavailable / disconnected, workspace archived) | `effectiveState` takes a single value |
| 7 | Test triggers in the wizard Review | Tests the UNSAVED draft in the browser with the shared evaluator (`evaluatePipelineTriggers`, the function the API and the router use); on T-27 and the row menu it calls the API for the saved version | The API dry run reads the stored configuration, never a draft |
| 8 | Duplicate through create (`copyFromPipelineId`) | `?copy=<id>` loads the source version into the wizard (name " copy"), then ordinary create | No server-side copy |
| 9 | Fork policy "disabled with a tooltip" | Option disabled plus a visible sentence under the field (works on touch and for screen readers) | Usability |
| 10 | Unsaved-changes guard on every exit | `beforeunload` plus a discard dialog on Cancel; sidebar links inside the app are not intercepted | `BrowserRouter` has no navigation blocker |
| 11 | "Save as version N+1" always publishes | With no configuration change nothing is published (name and description go through `PATCH`, not versioned) | R-3 |
| 12 | DAST and Asset Discovery "not selectable" | Shown as text badges "manual only (not available as a pipeline trigger)", no control | |
| 13 | Add pipeline as a button | A link button (opens `/pipelines/new?repository=`) | Middle-click, copy link |
| 14 | Plan limit message from the 403 only | Also from `options.pipelines` before the click (`limit` 0 reads as "your plan does not include pipelines"); the 403 `QUOTA_EXCEEDED` still shows the banner | |

`fullEvery` of the scan mode is preserved but not editable (SCREENS §5 step 4 does not list it). The T-24 Overview count and the T-22 column show a dash when the caller lacks `pipeline.view` (the API returns the count regardless).

### Verification matrix (headless Chrome against a disposable PostgreSQL, the GitHub stub, the API and Vite on private ports; 7 seeded roles)

Roles x screens (workspace Payments Platform; E enabled, D visible but disabled with the reason, H hidden/403 page, R read only). All cells match section 7.

| Screen / action | Admin | Manager | Lead | Analyst | Dev Lead | Developer | Viewer |
|---|---|---|---|---|---|---|---|
| Nav item, T-25, T-27, T-24 tab, real counts | E | E | E | R | E | R | R |
| Create / Add pipeline, wizard, edit route | E | E | E | H | E | H | H |
| Row/header switch | E | E | E | D | E | D | D |
| Run now (menu and T-27) | E | E | E | D | E | D | D |
| Edit, Duplicate | E | E | E | H | E | H | H |
| Delete | E | E | H | H | H | H | H |
| Test triggers | E | E | E | E | E | E | E |
| Fork policy "Run without credentials" | E | D | E | n/a | D | n/a | n/a |

Exercised: Manager creates a pipeline with push, pull request, schedule and manual triggers (fork policy stays `skip`, option disabled with the reason, the API answers 403 `fork_policy_requires_permission` to a forced attempt); Lead and Admin set it with the confirmation dialog (version 2, change note, diff, versions list, version selector); Manager opens a pipeline already at `run_without_credentials` (sees it, can only go back to `skip`); duplicate; `name_taken`; no-change save publishes nothing; metadata-only edit is not versioned; concurrent publish -> 409 banner "Reload the latest version" -> reload -> re-save as version 4; manual run (success queued row, transport failure then retry with the SAME Idempotency-Key, changed request gets a new key) and the refusal texts for a disabled pipeline, a switched-off manual trigger and a disconnected repository (stale page) plus the disabled-with-reason states after reload, a disabled repository and an archived workspace; enable/disable and `pipeline_incomplete`; soft delete with typed name (case sensitive), refusal while an execution is running (confirm stays disabled), delete with a queued request (cancelled, history kept), Show deleted, read-only deleted view, edit of a deleted pipeline is 404; dry run on T-27 (push would run, fork PR blocked by policy with the reason, invalid ref) and on the unsaved draft; Skipped events with one row of each source type (webhook delivery id, schedule slot with viewer-zone time and the UTC instant, manual key), the reason labels and the source filter; schedule errors (too frequent, unknown time zone, invalid expression) live, in the Review list with a "Fix in Triggers" link, and from the API (`VALIDATION_FAILED` on a tampered request mapped to the Triggers step); loading skeleton, 500 after retries with the reference and Try again, empty-by-filter with Clear filters, true empty (new workspace), no-permission page, not found (other workspace, unknown id, deleted edit), aliases; workspace switch keeps the section and filters; no horizontal overflow at 390, 820 and 1440 px on T-24 tab, T-25, all T-27 tabs and all wizard steps; keyboard order of the wizard (stepper buttons first, in step order, then fields, Cancel, Next; Enter on a step button changes the step).

Not verified or only partly: the plan-limit banner with a real limit (the demo plan allows 100; the banner was checked against a mocked 403 `QUOTA_EXCEEDED`); the viewer's empty T-24 tab and a denied executions tab (checked with mocked API answers); the DB row of a running execution was written through the disposable database (the public paths only create queued rows); Firefox and Safari; dark theme; screen-reader output beyond the roles, names and live regions in the markup; tenant-suspended states.

Defects found and fixed during the pass: `Intl` rejected `dateStyle` with `timeZoneName` (T-27 Overview crashed); step changes dropped the `repository` and `copy` parameters from the wizard URL (duplicate lost its source); the delete dialog showed a generic error instead of the API's reason; the wizard overflowed horizontally at 390 px (manual-only badges); disabled "Add pipeline" was a button, now a link button.

### As built 2026-11-13: wizard layout

T-26 now renders inside `WizardLayout` from `@qmentisai/ui` (pattern: `docs/design/UX_GUIDELINES.md` section 13). Header and summary stay put; the stepper stays put; only the form column scrolls; the action bar (Cancel on the left, Back / Next / Create on the right, top border) is always visible under the form. Below 1280 px the summary is a disclosure above the form; below 1024 px the stepper is a horizontal indicator.

**Validation covers the whole draft.** Create / Save stays disabled until it is valid, using (1) `createPipelineConfigSchema(options.limits)` from `@qmentisai/shared`, the API's own configuration schema, and (2) `checkBasics` in `features/pipelines/schemas/`, which mirrors the create/update request schema of `apps/api` (`pipelines/schemas/index.js`, not importable from the web app): repository is a UUID (path parameter in the API); name trimmed, 1 to 100 characters, no control characters; description trimmed, at most 500, no control characters; change note at most 200. Problems appear as an error icon with the text "(needs attention)" on the step (steps you have not opened stay quiet until Review; the step you are on shows its problems inline), in Review as "Field: message, Fix in <step>" links, and as "N problems to fix before saving" next to the button. Problems the server reported (`VALIDATION_FAILED`, mapped to the step as before) are shown but do not lock Create, so the next attempt can resend. The API stays authoritative.

**Review cards.** Definition lists are two-column grids (label 140 to 160 px, value `minmax(0,1fr)`); in a card narrower than 22 rem (two cards side by side at 1280 px) the label sits above the value so values never shrink to a few characters. Values wrap by word; only long mono values (patterns, globs, identifiers) use `overflow-wrap:anywhere`. Multi-value fields (branches, PR actions, tags, excluded paths) are wrapped chips. The header holds the title and the right-aligned On/Off badge; the trigger key shows only as a tooltip (schedule triggers also show it in the title, because several can exist). Grid: 2 columns from 1280 px, 1 below. The empty glyph is the em dash everywhere, including the summary ("None" and "none" are gone). `ConfigView` is shared with T-27 Configuration, which gets the same layout.

**Verification 2026-11-13** (headless Chrome 1280x720, 1440x900, 1024x768, 820x900, 390x800; disposable PostgreSQL, GitHub stub, API 4311, Vite 4312/4313; scripts outside the repository):
- Geometry: header, stepper, summary (>= 1280) and action bar had identical bounding boxes before and after scrolling the form column to 400 px, in all five viewports; the form column scrolled (scrollTop 400, window scrollY 0). `document.scrollingElement.scrollHeight <= innerHeight` in every case, including every T-26 step at 1280x720 and 1440x900 (form scrollHeight/clientHeight, e.g. Triggers 1467/499 at 1280x720).
- Focus: Tab through stepper, form and action bar on Triggers/Scans at 1280, 1440, 1024 and 390: no focused control hidden by the bar or clipped by the scroller, except one 7 px case at 390x800 (the lower edge of the `pr-exclude` textarea; Chrome scrolls only the caret line of a textarea into view, that line was visible).
- Review (edit mode of a pipeline with long branch/glob values, a schedule and all four triggers): no normal-text word rendered over two lines at 1280, 1440 and 1024 (Range rects per word), no `word-break:break-all`, no card overflow, chips wrap (4 of 5 chip lists wrapped), 2 card columns at 1280 and 1440, 1 at 1024; mono identifiers longer than the card were split (4 to 5 values), as intended; value column at least 204 px at 1280.
- Validation: empty Create review: Create disabled, Basics shows the error icon and "(needs attention)", two "Fix in Basics" links (Repository, Name); after filling them, Create enabled and the page says the pipeline is valid; a stubbed server 400 with `config.triggers.*` went to Triggers and with `name` to Basics; a real create navigated to the new pipeline.
- Below 1280: disclosure button with `aria-expanded` / `aria-controls` toggles by click and Space; stepper horizontal below 1024 (one row), vertical at 1024; one `aria-current="step"`; Tab order disclosure, stepper, form, action bar; focus ring is the 2 px ring colour.

### Wizard browser check (2026-11-13)

Headless Chrome at 1280x800 and 1440x800 on the five steps of T-26 (create route; Notifications hidden). Create was never clicked. Results: header, stepper, summary panel and action bar stay fixed while the form body scrolls (PASS); no horizontal page overflow (PASS); review cards show no character-per-line values, long values wrap at word, field or slash boundaries and only unbreakable tokens (a 50-character run, `America/Argentina/ComodRivadavia` at 1280) break mid-token (PASS); Create is disabled until every step is valid and the stepper marks the failing step, and it becomes enabled once the draft is valid (PASS). Not exercised: the execution-timeout error path, disabling all scans, the pending state, the Edit route, the Test triggers dialog. Observations: a React "Received NaN for the `min` attribute" console warning (component not yet identified) and long values carry no `title` attribute. Visual review by the owner is pending.

### As built 2026-11-13: T-25 columns and T-27 summary (tenant UI item 5, owner brief)

**T-25 columns (supersedes the table in section 4 for the built screen).** Before: Pipeline, Repository, Triggers, Scans, Last request, State, Enabled, Actions. Now: **Name** (link plus description; sortable), **Repository** (mono), **Last run** (the last request: outlined status chip with icon and text plus relative time; sortable by `lastRequestedAt`; it is the last execution request until execution statuses exist), **Enabled** (one column: the switch is the stored `enabled` flag, read only with a tooltip without `pipeline.manage`; next to it the derived effective-state chip, whose tooltip carries the reason, so the flag and the effective state both stay visible) and the row actions menu (unchanged). The State column is merged into Enabled; derived-state semantics are unchanged. Whole-row click and Enter on the focused row open T-27. Filters (search, repository, trigger type, state, show deleted), sort and paging are unchanged. The T-24 Pipelines tab uses the same table, so it also loses the Triggers and Scans columns.

**T-27 summary.** The Overview tab starts with a Summary section: **Triggers** (each trigger: type, Enabled or Disabled, and for schedules the cron description and the next run or "No upcoming run"; from the pipeline DTO plus the current version for the cron text), **Scans enabled** (chips from the current configuration version), Success rate and Open findings stay **hidden until the execution and findings modules exist** (owner decision C6; no placeholders). No API change.

No deviation from §8 difference 2 (owner decision C6): last duration, success rate, open findings, history strip and trend stay hidden.

**Wizard fix.** React warned "Received NaN for the `min` attribute" on the Execution controls step: `GET /pipelines/options` returns only the configurable limits (no `timeoutMinSeconds`, `scanTaskTimeoutMinSeconds`), so `Math.ceil(undefined / 60)` was NaN. The wizard now merges `DEFAULT_PIPELINE_LIMITS` from `@qmentisai/shared` under the API values (also used by client validation).

### As built 2026-11-13: T-25 Load more, no totals (tenant UI item 4, owner brief)

T-25 and the T-24 Pipelines tab no longer show a total ("N pipelines") or the page-number pager. The first request has `limit=20` (tab: 20) and no cursor; the footer **Load more** fetches `cursor=meta.pagination.nextCursor` and appends rows (`useInfiniteQuery`), and disappears on the last page. Search, repository, trigger, state, Show deleted and sort stay in the URL and in the query key: any change resets the list to the first page and the cursor is never reused. `INVALID_CURSOR` (400) restarts from the first page with a toast. Focus moves to the first new row and a live region says "More rows loaded". Loading, empty, empty-by-filter (Clear filters), error and no-permission states are unchanged. This supersedes "paging unchanged" in the 2026-11-13 columns note above.

