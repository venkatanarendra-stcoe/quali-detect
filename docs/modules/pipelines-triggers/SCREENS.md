# Screens: pipelines and triggers

Status: **Approved (2026-11-12)**, companion to `SPEC.md` of this module (decisions applied at approval are listed there). Nothing here is built yet. The identifiers, routes and prompts come from `docs/TENANT_APP_WIREFRAME_SPEC.md` (WF §5 inventory, §6 prompts T-24 to T-27, §4 RBAC); the existing built screens are described in `docs/modules/repositories-github/SCREENS.md`. Visual rules: `docs/design/DESIGN_SYSTEM.md` and `UX_GUIDELINES.md` (Geist Sans, mono only for identifiers such as repository full names, branch names, SHAs, cron expressions and pipeline keys, Lucide icons, **mint only for the primary action, active navigation and focus**, severity colors independent of the brand and never the only signal, status as an outlined chip with icon and text). Labels as in the SPEC: **Confirmed**, **Confirmed (owner, 2026-11-12)**, **Recommended — default applied**, **Open**.

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
| 4 | Overview "Pipelines" shows the real count and links to the tab; empty value "0" keeps a link "Add pipeline" for `pipeline.manage` holders | Count comes from the pipelines module through the repository DTO; `null` (hidden) if the caller lacks `pipeline.view` |
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
| Executions | two parts. **Requests:** minimal list of execution requests (status chip, trigger icon and "PR #214" / "push to main" / "schedule" / "by name", ref, commit SHA mono, scan kind, trust badge for forks, time); Cancel for `queued` rows (`execution.cancel`); reason text for Blocked and Skipped. **Skipped events:** list of trigger decision rows (time, trigger, ref or "PR #214", reason such as "Fork pull request, policy is Do not run", "Draft pull request", "Repository disconnected", "Pipeline disabled"), from `GET /pipelines/{id}/trigger-decisions`; **schedule skips appear here too** (owner decision 2026-11-13, SPEC §5.9b, §7.8): the row shows the **slot time** (`scheduleSlot`, in the viewer's time zone with the UTC instant as a tooltip), the **trigger** (key and a schedule icon, "schedule nightly") and the reason ("Repository disconnected", "Repository disabled", "Workspace archived", "Pipeline disabled") instead of a PR number or ref; the list can be filtered by source (`sourceType`: webhook event, schedule slot) and the SCM delivery id is shown only for webhook rows; events that did not match any trigger are not listed | rich list, detail links (T-28/T-29) |
| Findings | **hidden** until the Findings module (tab not rendered, no placeholder page) | |
| Configuration | read-only view of the current version with a version selector and a compare-with-previous diff; "Edit" opens the wizard | |
| Triggers | one card per trigger with its options, enabled switch (`pipeline.manage`; changing it publishes a new version, the dialog says so) and the schedule's next five fire times; "Test triggers" | |
| Activity | audit entries for this pipeline (`pipeline.*` incl. `pipeline.fork_policy_changed`, `execution.manual_requested`, `execution.manual_denied`, `execution.blocked`, `execution.skipped`) from the audit API, visible with `workspace.view_activity` (otherwise the tab is hidden) | |

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
