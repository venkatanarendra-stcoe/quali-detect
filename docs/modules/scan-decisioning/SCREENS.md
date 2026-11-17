# Screens: scan decisioning (T-29 "Analysis and decision")

Status: **Approved (2026-11-17)** with the SPEC of this module (owner approval). Nothing is built yet. This module adds **one section to T-29** (Execution detail, `docs/modules/executions/SCREENS.md` section 4) and changes nothing else on that screen, on T-28 or on navigation. Labels: **Confirmed** = the owner's 2026-11-17 brief; **Recommended** = my proposal; **Open** = needs the owner.

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
