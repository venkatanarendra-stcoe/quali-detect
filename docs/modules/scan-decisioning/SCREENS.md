# Screens: scan decisioning (T-29 "Analysis and decision")

Status: **Approved (2026-11-17)** with the SPEC of this module (owner approval). Built in part F (2026-11-18), see section 9 "As built" for what was and was not verified. This module adds **one section to T-29** (Execution detail, `docs/modules/executions/SCREENS.md` section 4) and changes nothing else on that screen, on T-28 or on navigation. Labels: **Confirmed** = the owner's 2026-11-17 brief; **Recommended** = my proposal; **Open** = needs the owner.

## Decisions applied from the brief

| Id | Effect | Label |
|---|---|---|
| D12 | T-29 shows an "Analysis and decision" section: a change summary, floor versus agent-added per scan type with reasons, the provider and model used, and a note when the run fell back to floor-only | Confirmed |
| SECURITY_GUIDELINES | Model output is labelled as such and shown with provenance (provider and model); rendered as text only | Confirmed (existing document) |
| New permission | None. The section needs `execution.view` like the rest of T-29. The permission key is never shown | Recommended |

## 1. Placement and frame

**Where (Recommended):** a collapsible card **"Analysis and decision"** between the Facts card and the Scan task cards, expanded by default while the execution is `preparing` or `running` and collapsed by default when it is finished, with the choice remembered per browser (UI state only, Zustand, not the URL). The stage timeline's **Preparing** stage gets a small sub-line "Analysis and decision" with the decision time once it exists. The card is a landmark region with a heading (h3) and `aria-expanded` on its toggle.

It appears **only when the API sends a `decision`** (section 5 of the SPEC, `GET /executions/{id}`). Executions created before this module have `decision = null`: **no card, no placeholder** (same rule as executions SCREENS B12: no placeholder for what does not exist).

## 2. Content (top to bottom)

### 2.1 Summary line
One sentence, plain text, built from facts, never from model text:
- full run: "Full scan: every enabled scan type was selected."
- incremental, diff complete: "Incremental scan: 12 files changed (3 dependency files, 7 source files, 2 other). 3 of 4 enabled scan types were selected."
- incremental, diff truncated or unavailable: "Incremental scan: the list of changed files could not be read completely, so every enabled scan type was selected." (icon + text)
- zero scans: "No scan applied to these changes." (status chip "Succeeded", reason "No scan applied"; no task cards)

### 2.2 Change summary
A compact definition list (not a table): changed files total; by class (dependency files, source files, configuration, documentation, other) with counts; by status (added, modified, removed, renamed) with counts; lines added and removed. Under "Show changed paths" (a disclosure, closed by default): up to 20 sample paths per class, **mono**, copyable, text only. A note when truncated: "Showing a sample; the full list is not stored." The list never contains file contents or patches (the API has none).

### 2.3 Decision per scan type (the main element)
A `DataTable`-style list, one row per **enabled** scan type plus a row for each **not enabled** type only if the pipeline snapshot has it disabled (muted, "Not enabled in this pipeline"). Order: SBOM, SCA, SAST, Secrets. Columns:

| Column | Content |
|---|---|
| Scan type | name (SBOM, SCA, SAST, Secrets) |
| Decision | chip with **icon + text** (never colour alone): **Required** (neutral/mint-free tone, check icon), **Added by assistant** (info tone, sparkle icon), **Not selected** (muted, minus icon), **Not enabled** (muted, dash) |
| Reason | for **Required**: the rule in words ("A dependency file changed", "Source code changed", "Any change is scanned for secrets", "Changed files could not be listed, so everything runs"); for **Added by assistant**: the model's reason (see 2.4); for **Not selected**: "No matching changes" |
| Task | link to the task card below ("View task") when a task exists, with its status chip (including "Not supported" for `unsupported`); an em dash when no task exists |

Rules: the wording of every **Required** reason comes from a fixed map of rule ids to text in the frontend (no model text, no free text from the API there). Rows are static text; no editing.

### 2.4 Assistant block
A bordered, neutral block titled **"Analysis assistant"** with:
- **Provider and model** in mono ("anthropic · model-name", "ollama · model-name"), and the caption "Written by a language model. It can only add scans; it cannot remove required ones. It may be inaccurate."
- The model **summary** and, in the table, each **reason**, as **plain escaped text** (no Markdown, no HTML, no links), clamped to 3 lines with "Show more".
- Usage line (muted): "1 call · 412 in / 96 out tokens · 3.1 s" (from `agent.usage`; hidden when no call was made).

### 2.5 Fallback note
Shown instead of (or above) the assistant block whenever `agent.status` is not `ok`; plain text with an icon, never a banner colour alone, never an error style (a floor-only run is a normal outcome):

| `agent.status` | Text |
|---|---|
| `not_configured` | "The analysis assistant is not configured. The required scans for these changes were selected." |
| `nothing_to_add` | "The assistant was not needed: every enabled scan type was already required." |
| `consent_required` | "The analysis assistant is turned off for your organization. The required scans for these changes were selected." |
| `skipped_fork` | "The assistant is not used for pull requests from forks. The required scans were selected." |
| `timeout` | "The assistant did not answer in time. The required scans were selected." |
| `error` | "The assistant was unavailable. The required scans were selected." |
| `invalid_output` | "The assistant's answer was not usable and was ignored. The required scans were selected." |
| `interrupted` | "The assistant was not asked again after a worker restart. The required scans were selected." |
| `cancelled` | "The run was cancelled during the analysis." |

When `status = ok` and there are no additions: "The assistant reviewed the changes and added no scans." The provider and model are shown whenever a call was made, including failed ones.

## 3. Other T-29 effects (small, Recommended)

- **Task cards:** only decided tasks exist, so a not-selected type has **no task card**; it is visible only in 2.3 (so the "3/4" style counters in the header use the number of created tasks, and the label stays "scans" not "enabled scans"; a run with fewer tasks than enabled types is not shown as partial).
- **Notices:** the existing "not resolution-eligible" and fork notices are unchanged.
- **Events tab:** two new rows: "Analysis started" (`decision_started`) and "Analysis completed" (`decision_completed`, with the final scan types in words). A recovery row keeps its text. Reasons from the model are not repeated here.
- **Stage timeline:** unchanged stages; the sub-line described in section 1.
- **Logs tab:** the existing execution log gets decision lines (info level, ids and counts only), for example "analysis: 12 changed files, required scan types sbom, sca, secrets" and "analysis: assistant not configured".

## 3b. Consent switch (tenant Settings, small addition, Recommended placement)

A card **"Analysis assistant"** on the existing tenant Settings page (visible with `tenant_settings.view`, editable with `tenant_settings.manage`): a switch "Allow external AI providers to receive file names of your repositories" (default off) with the explanation "When off, your scans are chosen by fixed rules only, unless this platform uses a local model. File names and change counts, never file contents, are sent. Changes are recorded in the audit log." Shows who changed it and when. Turning it on asks for confirmation. Loading, error and no-permission states follow the Settings page. The switch is shown only when the deployment has an external provider configured (otherwise the card says the assistant is not configured).

## 4. States

| State | Behaviour |
|---|---|
| Loading | the card shows a skeleton with the heading |
| `decision = null` | no card |
| Preparing, not decided yet | card with the text "Analysis in progress." and an indeterminate indicator; no percentage (the API provides none) |
| Error | the page-level error handling of T-29 applies (retry plus correlation id); the card has no separate error state |
| No permission / hidden / other tenant | the page-level states of T-29; the card never renders |
| Zero scans | summary line per 2.1 and an empty-style note in 2.3 ("No scan applied to these changes."); the scan unit was returned |
| Narrow (1280) | change summary and assistant block stack; the table keeps all four columns with the Reason wrapping |

## 5. Realtime
The card refetches the detail on the new hint `pipeline.execution.decision_completed` (ids only) and on the usual status hints. No model text travels through Socket.IO.

## 6. Accessibility and design tokens
Chips carry icon and text; the sparkle icon is Lucide `Sparkles`, the required icon `Check`, the not-selected icon `Minus`. No mint except the existing primary action and focus (DESIGN_SYSTEM); the "Added by assistant" tone is the existing info neutral, not a new colour. Mono only for identifiers (provider, model, paths, rule ids). The disclosure and the clamp are keyboard operable with visible focus; the "Show more" button announces its state. All model text is escaped.

## 7. Verification matrix (to be run by hand after implementation; nothing is claimed)
All seven default roles on the section (visible with `execution.view`, absent otherwise); each `agent.status` row of 2.5; full run, incremental with diff complete, truncated and unavailable; fork pull request; execution without a decision; zero scans (once decided); reclaim during `preparing`; light and dark themes; 1280 and 1440 px; keyboard only; a hostile reason string (HTML, Markdown, very long, control characters) rendered as inert text.

## 8. Open points for the owner
1. Placement as a card between Facts and Task cards, versus a new **Analysis** tab (Recommended: card; a tab hides a result the user needs at a glance).
2. The label "Analysis assistant" and the chip wording "Added by assistant" (product naming; no "AI" claim beyond what the block says).
3. Whether sample paths are shown at all (they are stored only as a capped, redacted sample; SPEC OQ and section 7.2).
4. Where the consent switch lives in the tenant Settings screen (the SPEC adds `GET/PUT /settings/ai`; the toggle is a small card on the existing Settings page, section 3b below).

## 9. As built (part F, 2026-11-18)

Frontend only (`apps/tenant-web`); no backend, database or contract change. The sections above stay the approved specification.

**Files.** Executions feature: `components/analysis-card.jsx` (the card), `components/inert-text.jsx` (`ClampedText`, `InertMono`), `constants/decision-rules.js` (fixed maps: rule id to text, `agent.status` to the 2.5 sentences, chip labels, class and status wording), `constants/decision-text.js` (pure builders: `inertText`, `summaryLine`, `requiredReasonText`, `finalTypes`, `scanTypesInWords`, `usageLine`, `providerLine`, `analysisCompletedLabel`, `samplesTruncated`), `stores/analysis-card-store.js` (Zustand, persisted in `localStorage` through `safeStorage`, key `qm-analysis-card`), edits in `execution-detail-page.jsx`, `stage-timeline.jsx`, `events-tab.jsx`, `task-cards.jsx`, `constants/index.js`, `schemas/realtime.js`. Organization feature: `components/analysis-assistant-card.jsx`, `hooks/use-ai-settings.js`, `services/ai-settings-service.js`, `pages/organization-settings-page.jsx`; the `settings` route in `app/routes.jsx` now renders this page instead of the "planned" placeholder.

**Behavior as built.**
- The card sits in the left column of T-29 between the stage timeline and the Scans cards (the Facts card is the right column at 1440 px and comes last when narrow, so "between Facts and task cards" is read as "above the task cards"). It renders when `detail.decision != null`, and also as "Analysis in progress." while the status is `preparing` and there is no decision yet (the brief asked for this state; section 1 says no card for `decision = null`, which still holds for every other status).
- Heading level is h2 (the page has an h1 and the Scans section is an h2; SCREENS said h3). The toggle button carries `aria-expanded` and `aria-controls`. Default open: `preparing` and `running`; closed otherwise; once the person toggles, the choice (one value for all executions) is remembered in this browser.
- Required reasons come from the fixed map of rule ids `FL-1..FL-5` (`FLOOR_RULES` in `@qmentisai/shared`); an unknown id gives "Required by a fixed rule". Under the `strict` Secrets mode FL-3 reads "Any changed file, removals included, is scanned for secrets" (the API sends `secretsRule`). The not-selected code `no_matching_changes` maps to "No matching changes"; unknown codes to a generic sentence.
- Model text (assistant summary, reasons, provider, model, sample paths) passes `inertText` (non-strings dropped; control, zero-width, bidirectional and line-separator characters replaced by a space; whitespace collapsed; length cap with an ellipsis) and is rendered as a React text child: no `dangerouslySetInnerHTML`, no Markdown, no links, wrapped anywhere (`overflow-wrap:anywhere`). Summary and reasons are clamped to 3 lines with a "Show more" button (`aria-expanded`), shown only when the text overflows.
- The usage line is "412 in / 96 out tokens · 3.1 s". The "1 call" part of 2.4 is not shown: the DTO deliberately carries no turn count (DEC-S13 asserts it).
- "View task" moves focus to the task card toggle (DOM id from the task id). Task-card header counters: nothing changed, the Scans section has no counter and the list's `TaskSegments` already uses `taskSummary.total` (created tasks).
- Events tab: `decision_started` reads "Analysis started"; `decision_completed` reads "Analysis completed: SBOM, SCA and Secrets scans". The events DTO has no details, so the scan types come from the execution's `decision`, passed to the tab; without it the row reads "Analysis completed". The zero-scan reason `no_applicable_scans` reads "No scan applied". The Logs tab is unchanged (the logs API sends whatever lines exist).
- Stage timeline: the Preparing stage shows "Analysis and decision <time>" once `decision.decidedAt` exists.
- Realtime: the API relays the hint `pipeline.execution.decision_completed` to the browser as the Socket.IO event `execution.decision` (ids and `rev` only). The page refetches the detail and the events on it; nothing is read from the hint.
- Consent card (3b): on the organization Settings page (route `/settings`, `tenant_settings.view`). `GET/PUT /settings/ai` with body `{ externalConsent }`. Seen with `tenant_settings.view`, the switch is editable only with `tenant_settings.manage` (otherwise disabled with a note). Turning it on opens a confirmation dialog; turning it off saves directly. The cache is replaced with the server answer (no optimistic write). States: loading skeleton, error with retry, no permission, "not configured" (`assistant.configured = false`, no switch), local model (`providerKind = local`: a note, no switch, because a local model needs no consent), external (switch). Permission keys are never shown; checks go through `useCan`.

**Contradiction found, not papered over.** 3b says the card "shows who changed it and when". `GET /settings/ai` returns `consentChangedAt` and `updatedAt` but no actor (the row stores `updated_by_user_id`, the DTO does not expose it; the actor is in the audit log). The card shows the time only. Needs an owner decision: add a changer display name to the DTO (backend change) or amend this section.

**Verification status (honest).**
- Run: `pnpm lint` (0 errors), `pnpm build --force`, `npx prettier --check .`, `pnpm install --frozen-lockfile --offline`, `pnpm contract:parity`, `pnpm test:security` (frontend is outside its scope, run as a regression gate only); a one-off server-side render of `AnalysisCard` with a hostile fixture (HTML, Markdown, a `javascript:` link, a right-to-left override, a NUL, 5000 characters) using `react-dom/server`, which showed the markup as escaped text, no element created, the control characters removed and the long text cut; a node run of the pure builders (`inertText`, `summaryLine`, `requiredReasonText`, `analysisCompletedLabel`). No test file was added (frontend tests are out of scope).
- **NOT verified: any visual or browser check.** No browser tool was available. Not seen in a browser: layout at 1280 and 1440 px, light and dark themes, focus rings, the 3-line clamp and the "Show more" overflow detection (it measures `scrollHeight`, which only runs in a browser), the native disclosure, the consent dialog, keyboard-only use, the live refetch on the `execution.decision` hint, the persisted collapse choice, and the settings page with the seven default roles. Not run against a real decision: the dev database has not had the part E migration applied by this work, so no execution with a `decision` was loaded.
- Hostile-string matrix for the manual pass (**not yet run**): a reason, summary, model name and sample path each containing `<script>alert(1)</script>`, `<img src=x onerror=alert(1)>`, `**bold**`, `[link](javascript:alert(1))`, a 5000-character unbroken word, a right-to-left override (U+202E), NUL and other C0 characters, line breaks, and an emoji; expected result for each: shown as inert single-line text, nothing executes, no link or bold, the page does not widen, "Show more" works with the keyboard.
- Section 7's matrix (seven roles, every `agent.status`, full/incremental/truncated/unavailable, fork, no decision, zero scans, reclaim, themes, sizes, keyboard) is **not yet run**.
