# Screens: findings (T-31 to T-36 and AiAdvisoryCard)

Status: **Draft for owner approval (2026-11-23)** with `SPEC.md` of this module. Nothing is built. Identifiers, routes and prompts come from `docs/TENANT_APP_WIREFRAME_SPEC.md` (inventory rows T-31 to T-36 and their prompts), `docs/design/TENANT_APPLICATION_DESIGN.md` 3.7 to 3.11, `docs/design/UX_GUIDELINES.md` and `docs/design/DESIGN_SYSTEM.md`. Numbers T-31 to T-36 are free and match the owner's assignment (highest used number in the repository is T-45); the contradictions with the wireframe are SPEC 0.3.

## Decisions applied

| Id | Effect on the screens | Label |
|---|---|---|
| D-3, SPEC 6.1 | Status labels of section 2; board columns are five (SPEC C-3) | Confirmed |
| D-4 | Approve and Reject disabled with a tooltip for the reviewer; the server decides (`canDecide`) | Confirmed |
| D-6 | `AiAdvisoryCard` is advisory only, never styled as a decision, always "requires a human decision" | Confirmed |
| D-10 | The four navigation items become implemented with their existing permission keys | Confirmed |
| SPEC D-20, D-22, D-23, D-28, D-29 | Approval of both decision kinds, the `approved` state, "Start review", one dialog for accept risk and suppression, bulk Assign and Start review only (no Export, no bulk decisions) | Recommended |
| WF C-11 | No DAST filter; "AI suggestion" filter added; the ticket key is text without a link | Recommended |

## 1. Common rules

- **Feature folder** `apps/tenant-web/src/features/findings/` (`components/ pages/ hooks/ services/ schemas/ stores/ constants/ index.js`). TanStack Query owns server data (keys start with tenant, workspace, `findings`); filters, sort, page and the selected finding are **URL parameters**; Zustand only UI state (panel widths, selection, density).
- **Permissions and states of actions** come from the central authorization engine and from `lifecycle.allowedActions` of the DTO (SPEC 8.3); **no role names in UI code**. An action the user can never perform is hidden; an action they may reasonably request but cannot right now is **disabled with a tooltip** that says why in words ("You need permission to assign findings", "You recorded a decision on this finding. Another lead must approve it.", "The finding changed. Reload to continue."). The permission key is never shown. The backend enforces everything (a stale button still gets 403, 404 or 409).
- **Every data view** has loading (skeleton shaped like the content), empty, empty-by-filter (with "Clear filters"), error (retry and correlation id) and **no-permission** states. A finding in another workspace, another tenant or nonexistent is the same **not found** page.
- **Untrusted text** (titles, rule names, paths, snippets, rationales, comments, the model's reasoning, PR URLs) is rendered as escaped plain text, never HTML or Markdown. Identifiers (fingerprint, commit sha, rule id, path, component) are **mono** with middle truncation, a copy button and the full value in a tooltip. Times are relative with the absolute time in a tooltip and `<time datetime>`.
- **Mint** only for the active navigation item, the focus ring and the page's one primary action. Severity colors never reuse mint; the accent never appears on a status or on `AiAdvisoryCard`.
- **Severity** = filled tint pill with icon and label (`SeverityBadge`, tokens `--sev-*`); **status** = outlined chip with leading icon (`StatusBadge`, tokens `--status-*`); color is never the only signal (DESIGN_SYSTEM 2.2, 2.3).
- **Pagination:** numbered pages (first, previous, numbers with ellipsis, next, last), page size 25, 50, 100, "Page X of Y · N findings" (the total only in the pager); `page` and `pageSize` in the URL. The board columns use "Load more".
- **Realtime:** hints (SPEC 9.5) invalidate queries; if the socket is down, poll every 60 s and refetch on focus. A transition happening while a user edits shows "This finding changed" with a Reload action; a 409 never loses the typed rationale.
- **Free-text forms** (rationale, justification, comment) show a live character counter and, on a `credential_shape` refusal, the message "This text looks like a secret or credential. Remove it and try again." with the offending field focused.
- **Themes and density:** dark and light tokens; compact density from the user preferences; no local storage of server data.

## 2. Status and SLA presentation (extends DESIGN_SYSTEM "Findings", Recommended)

| Status | Label | Icon | Tone | Meaning |
|---|---|---|---|---|
| `new` | New | `circle-dot` | neutral | Detected, not yet in review |
| `in_review` | In review | `eye` | neutral | An analyst is reviewing (shows "by <name>" when claimed) |
| `awaiting_approval` | Awaiting approval | `clock` | warning | A decision (TP or FP) waits for a lead |
| `approved` | Confirmed, unassigned | `shield-alert` | danger | True positive approved, needs an owner |
| `false_positive` | False positive | `shield-off` | neutral, muted | Approved as not a real issue |
| `assigned` | Assigned | `user-check` | neutral | A developer owns the fix |
| `in_remediation` | In progress | `wrench` | neutral | Work started |
| `fixed_pending_verification` | Fixed, pending verification | `scan-search` | warning | Waiting for the next complete scan; never shown as fixed |
| `verified_fixed` | Verified fixed | `circle-check` | success | Verified by a complete scan |
| `reopened` | Reopened | `rotate-ccw` | warning | Detected again, or an exception ended |
| `accepted_risk` | Accepted risk | `shield-check` | neutral | Until the shown expiry date |
| `suppressed` | Suppressed | `eye-off` | neutral, muted | Hidden by an approved request |

SLA chip (icon + text + the due date in a tooltip): `on_track` "7 d left" (`timer`, neutral), `due_soon` "Due in 2 d" (`timer`, warning), `breached` "Overdue 3 d" (`alarm-clock`, danger), `not_applicable` an em dash. The countdown never shows for closed findings. Recurrence icon (`repeat`) with "Reopened N times" when `reopenCount > 0`. Chips "Pipeline deleted" and "Not scanned recently" (neutral, `info`) where the DTO says so.

## 3. Screen inventory

| ID | Screen | Route (workspace-nested; the wireframe route `/findings/:id` redirects) | Route permission | Data (SPEC 8) |
|---|---|---|---|---|
| T-31 | Findings list | `/workspaces/:workspaceId/findings` | `finding.view` | `GET /findings`, `GET /findings/summary`, `GET /pipelines?workspaceId=` (filter options), bulk routes |
| T-32 | Finding detail | `/workspaces/:workspaceId/findings/:findingId` (alias `/findings/:findingId` resolves the workspace through `GET /findings/{id}`; a 404 stays 404) | `finding.view` | `GET /findings/{id}`, `/history`, `/comments`, `/similar`, the write routes |
| T-33 | Accept-risk and suppression dialog | dialog on T-32 and T-31 rows | `finding.accept_risk` or `finding.suppress` | `POST /findings/{id}/exceptions` |
| T-34 | Reviews queue (nav "Security Reviews") | `/workspaces/:workspaceId/reviews` | `security_review.view` | `GET /review-queue`, `GET /findings/{id}`, review routes |
| T-35 | Approvals queue | `/workspaces/:workspaceId/approvals` | `approval.view` | `GET /approvals`, approve and reject routes |
| T-36 | Remediation board | `/workspaces/:workspaceId/remediation` | `remediation.view` | `GET /remediation/board`, column paging, remediation and assignment routes |
| (component) | `AiAdvisoryCard` | inside T-32 and T-34 | follows the host screen | the `advisory` object of the finding DTO |
| (section) | SLA targets | tenant Settings, "Findings" section | `tenant_settings.view`, `.manage` | `GET`/`PUT /settings/findings-sla` |
| (section) | Code-excerpt consent switch | tenant Settings, the existing "AI assistant" card | `tenant_settings.manage` | `GET`/`PUT /settings/ai` |

**Navigation change (exact, Part E).** In `packages/shared/src/navigation.js`, group `security` of `WORKSPACE_NAV_GROUPS`: `item("findings", "finding.view", "workspace", false)` becomes `true`; `item("security-reviews", "security_review.view", "workspace", false)` becomes `true`; `item("approvals", "approval.view", "workspace", false)` becomes `true`; `item("remediation", "remediation.view", "workspace", false)` becomes `true`. Ids, permission keys and scopes unchanged; no role check. Routes are registered in `apps/tenant-web/src/app/routes.jsx` (so `isRouteAvailable` holds); `policies` and `reports` stay unimplemented. Counts (numbers in the nav) appear only on Findings (open findings needing attention: `needsReview`), Security Reviews (`needsReview`) and Approvals (`pendingApprovals`) from `GET /findings/summary`, hidden at zero. **Permission keys used by this module:** `finding.view`, `finding.comment`, `security_review.view`, `finding.review`, `approval.view`, `approval.approve`, `approval.reject`, `finding.assign`, `remediation.view`, `finding.remediate`, `finding.suppress`, `finding.accept_risk`, `tenant_settings.view`, `tenant_settings.manage`. No new key; the bundle additions proposed in SPEC 3.2 change who holds `finding.accept_risk` and `finding.suppress` only.

## 4. T-31 Findings list

**Purpose:** find, filter and triage the workspace's findings. **Frame:** the workspace layout page with a header, saved-view tabs, a filter bar, one table card and the pager (UX_GUIDELINES list template).

**Layout.** Header: title "Findings", a muted count. Saved-view tabs with counts from the summary: **All open**, **Needs review**, **Assigned to me**, **Breached SLA** (SPEC 5.11); the default tab is "Assigned to me" when the caller can remediate but not review (decided from `lifecycle`-style flags of the summary response `defaultView`, never from a role name), otherwise "All open". Filter bar (collapsible left panel on wide screens, a sheet on narrow): Severity (checkboxes with severity dots and icons), Status (the 12 labels), Scan type (SCA, SAST, Secrets), Pipeline, Repository, Assignee (Me, Unassigned, a member), SLA (On track, Due soon, Breached), AI suggestion (Likely TP, Likely FP, Uncertain, None), search box (rule, path, title; 2 to 100 characters). Active filters appear as removable chips above the table with "Clear all".

**Table columns** (checkbox, then): Severity (`SeverityBadge`), Title (text, two lines max, with the rule id in mono below), Location (path:line mono, middle-truncated; for SCA the component `name@version`), Pipeline (name; "deleted" chip when so), Status (`StatusBadge`; "In review by Ana" when claimed), SLA chip, Assignee (avatar and name, or "Unassigned"), AI (a small `AiAdvisoryCard` hint chip "Likely TP 87%" in the neutral advisory style, never in a status color, only when `ready`), First seen (relative), Recurrence icon. Sortable: Severity (default, high first), SLA, First seen, Last seen, Title (URL `sort`). Row click opens T-32 (a real link; middle-click works); the checkbox does not.

**Bulk actions** (appear when at least one row is selected, at most 50, same workspace; D-29): **Start review** (`finding.review`, only rows in `new`) and **Assign** (`finding.assign`, only approved, assigned, in-progress or reopened rows) with an assignee picker; no Export, no bulk decision. Eligibility is explained: "3 of 7 selected findings can't be assigned (not confirmed yet)". The result dialog lists per-finding outcomes from the bulk response. Actions the user can never perform are hidden.

**Primary action:** none (no mint button on this page).

**States.** Loading: table skeleton (8 rows) and tab-count skeletons. Empty (no findings at all in the workspace): "No findings yet. Findings appear after a scan of the default branch finds issues." with a link to Pipelines (shown only with `pipeline.view`). Empty by filter: "No findings match these filters." and Clear filters. Error: message, Retry and the correlation id. No permission: "You don't have access to findings in this workspace." Not found workspace: the standard not-found page. Partial realtime failure: a quiet "Live updates paused" caption.

**Interactions.** Tabs set `view`; filters update the URL and reset to page 1; keyboard: `/` focuses search, arrow keys move between rows in the table (roving tabindex), `Enter` opens the focused row, `Space` toggles its checkbox. **A11y:** a real table with column headers and `aria-sort`; severity and status carry icon and text; the SLA chip text includes the state word; selection count announced with `aria-live="polite"`; focus returns to the row after closing a sheet; filter panel is a labelled form region. **Responsive:** below 1024 px the filter panel becomes a sheet; below 768 px the table becomes a card list (severity, title, status, SLA) with the same actions; no horizontal page scroll.

**Tokens and copy.** `--sev-*`, `--status-*`, `--card`, `--border`; Geist Sans, mono only for rule ids, paths, components and fingerprints; Lucide icons as in section 2; sentence case; tab labels as above; tooltips for truncated values.

## 5. T-33 Accept-risk and suppression dialog

**Purpose:** request that a finding be accepted as a risk for a limited time, or suppressed, with a lead's approval. **Where:** a dialog opened from T-32 ("Request accepted risk", "Request suppression" in the actions menu) and from a T-31 row menu. **Permission:** `finding.accept_risk` for accept risk, `finding.suppress` for suppression; the menu item is hidden without the key. **API:** `POST /findings/{id}/exceptions`.

**Layout.** Title "Request accepted risk" or "Request suppression" (a two-option segmented control at the top switches the kind and hides an option the user may not use). Info line (accept risk): "Accepted risk is time-bound and requires approval by a lead. The finding stays visible and is reopened automatically when it expires." (suppression): "Suppression hides this finding only, in this pipeline. It requires approval, and you can set an expiry." Fields: **Risk statement / justification** (textarea, required, 20 to 2000, counter); **Compensating controls** (textarea, optional, accept risk only, up to 1000); **Expiry date** (date picker, **required** for accept risk, today plus 1 day to plus 180 days, with presets 30, 90, 180 days; optional for suppression, up to 365 days, "No expiry" allowed); **Requested approver** (optional select of active members who may approve, excluding yourself; helper text "Any eligible lead can decide; this only notifies your choice"). SOD note (always visible, with an `info` icon): "You can't approve your own request. A different person with approval rights decides." A summary row shows the finding's severity, title and current status. No attachments in v1. Buttons: Cancel and **Submit for approval** (the page's primary action while the dialog is open: mint).

**States.** Submitting: button spinner and disabled fields; success: dialog closes, toast "Request submitted for approval", T-32 shows the pending exception banner "Accepted risk requested by Ana, waiting for approval" with a Withdraw link for the requester. Validation errors inline (expiry out of range, justification too short, credential shape); `409` (finding changed or a request already pending): "This finding changed or already has a pending request" with Reload. A finding in a state that cannot take a request disables the entry with the tooltip "This finding can't take a request in its current status." No-permission: the entry is hidden.

**A11y.** Focus trapped in the dialog, first field focused, `Escape` cancels, the date picker is keyboard operable and the typed date is accepted (format hint shown), errors linked with `aria-describedby`. **Responsive:** full-screen sheet below 640 px.

## 6. T-32 Finding detail

**Purpose:** everything about one finding, its evidence, its decisions and the actions allowed now. **Frame:** the workspace layout; a back link "Findings" preserving the list's URL state.

**Header (two lines).** Severity badge, title (escaped text), `StatusBadge` (with "pending TP decision" or "pending FP decision" detail when awaiting approval, and the expiry date for accepted risk), SLA chip, recurrence icon; second line: fingerprint (mono, short with copy copying the full `fp1:` value), pipeline chip and repository chip (links), scan type, rule id and CWE (mono), the tools that detected it ("Detected by Trivy, OSV-Scanner"). Banners (neutral, icon and text) when relevant: "Pipeline deleted. Verification is paused.", "Repository disconnected. Verification is paused.", "Not scanned recently: this scan type is no longer enabled.", "Accepted risk until <date>", the pending-exception banner.

**Actions (header right).** Rendered from `lifecycle.allowedActions`; at most one primary (mint) per state, in this order of precedence: "Start review" (new), "Record decision" (in review), "Assign" (approved or reopened), "Start work" (assigned), "Submit fix" (in progress). Others in a menu: Claim or take over, Withdraw decision (own pending decision), Reopen for review, Approve, Reject, Assign or Reassign, Unassign, Request accepted risk, Request suppression, Revoke acceptance, Request advisory again. Approve and Reject appear for approvers; for the reviewer they are **disabled with the tooltip** "You recorded a decision on this finding. Another lead must approve it." Disabled actions show the server's `disabledReason` in words.

**Tabs** (URL `tab`): **Overview** (default), **Evidence**, **History**, **Comments (n)**.

- **Overview** (main column): description of the issue from structured data (rule, advisory ids with family, CWE, affected component and version, **fixed versions** for SCA "Upgrade to 4.17.21 or later" as data), the **location** with the code viewer (below), `AiAdvisoryCard` (section 9), the current decision block (who decided TP or FP, rationale, optional severity override "Raised from Medium to High by review", when), the pending exception block, the remediation block (assignee, notes, PR link as a safe link, ticket key as text). Right column: **Risk card** (severity, tool severity, confidence, "Reviewed" marker), **SLA card** (target, started, due, a countdown that updates each minute, state chip), **Assignee** card, **Detections** card ("First seen", "Last seen", "Seen N times", "Reopened N times"), **Similar in other pipelines** (links only, "Not merged: each pipeline tracks its own finding", from `/similar`), ticket key text.
- **Evidence:** the code viewer with line numbers: for SAST the **enclosing function or block** (`nodeKind`, language) with the focus lines highlighted (background tint plus a left bar and `aria-label` "highlighted lines 55 to 57", not color alone); for a **secret** the **masked line preview** with its masked context ("`AWS_ACCESS_KEY_ID=[REDACTED:aws_access_key]`"), the note "The value is never stored. Rotate it if it is real." and **no** copy-snippet button; for SCA the component, versions and advisory list instead of code. Above the viewer: the **commit-pinned link** "View at commit a1b2c3d on GitHub" (mono short sha; opens in a new tab with `rel="noopener noreferrer"`; shown only when the DTO `link.url` is non-null; otherwise "No link available"), file path and line range, and the capture time. A truncated snippet shows "Excerpt shortened". A purged snippet shows "The code excerpt was removed after the retention period; the link and line numbers remain." A finding without evidence shows "No code excerpt is available for this finding." The snippet is inert text in a mono, horizontally scrollable region with a keyboard-focusable container; long lines are not wrapped by default (a "Wrap lines" toggle).
- **History:** the immutable timeline (newest first, keyset "Load more"): detected, claimed, decision recorded (TP or FP with rationale), withdrawn, approved or rejected (with comment), assigned, work started, fix submitted, auto-detected absent, verified fixed, reopened (recurred, risk expired), exception events, severity override, each with the actor (name, or "System") and a relative time with the absolute time in a tooltip; system rows use the system icon. Rationales are plain text, clamped to 4 lines with "Show more".
- **Comments:** list (author, time, plain text) and a composer (`finding.comment`; hidden without it, replaced by "You can read comments but not add them"), counter, Submit comment; no edit or delete (OQ-7).

**Dialogs started here.** **Record decision** (opens the decision form of section 7 as a dialog on T-32: radio True positive / False positive (none preselected), rationale (required, 10 to 2000), severity override select (enabled only for True positive), Submit for approval); **Approve** and **Reject with comment** confirmation dialogs (Reject requires a comment); **Assign** (member picker listing only eligible assignees, note); **Submit fix** (PR URL, ticket key, note, with the sentence "This marks the fix as submitted. It becomes Verified fixed only after the next complete scan finds it gone."); **Revoke** (reason); T-33.

**States.** Loading: header and tab skeletons. Error with retry and correlation id. No permission or not found: the not-found page. Conflict (409): inline banner "This finding changed. Reload to continue." with Reload. Realtime updates are applied without losing a typed rationale. **A11y:** the page has one `h1` (the title); tabs follow the ARIA tabs pattern with arrow keys; the history is an ordered list; status and SLA announce changes through a polite live region; buttons have visible focus rings; the countdown is not announced every minute. **Responsive:** the right column moves below the main column under 1024 px; the action menu collapses to a "Actions" button under 640 px.

## 7. T-34 Reviews queue

**Purpose:** analysts work through findings that need a decision. **Route and nav:** `/workspaces/:workspaceId/reviews`, nav item "Security Reviews". **Permission:** `security_review.view` to see the page; deciding needs `finding.review` (without it the decision form is replaced by "You can read this queue but not record decisions").

**Layout (split view, UX_GUIDELINES queue template).** Left: the queue list (findings in `new` or `in_review`), a filter strip (severity, pipeline, scan type, "Mine", "Unclaimed", AI suggestion) and sort (oldest first by default, severity, SLA); each row: severity badge, title, pipeline, age, "In review by Ana" or "Unclaimed", the advisory chip "Likely TP 87%" (advisory style). Right: the review panel for the selected finding (selection in the URL `finding`): header (severity, title, rule, location), evidence summary and the code viewer (same component as T-32 Evidence, shortened), the **`AiAdvisoryCard`** (state-dependent), a "Open full detail" link, and the **decision form**: radio **True positive** / **False positive** (neither preselected, never preselected from the advisory), **Rationale** (required, 10 to 2000, counter), **Severity override** select (only when True positive; "Keep tool severity (High)" default), and the primary button **Submit for approval**. A "Start review" button appears first for unclaimed findings (claims it; claimed by someone else shows "Take over" with a confirmation). The helper line under the form: "A lead who did not record this decision will approve it."

**Keyboard** (hints at the bottom, a visible legend and `aria-keyshortcuts`): `J` / `K` next and previous finding, `T` choose True positive, `F` choose False positive, `R` focus the rationale, `Ctrl+Enter` submit. Shortcuts are disabled while typing in a field and can be turned off. Submitting moves the selection to the next finding and announces "Decision submitted for approval. Next finding selected." through a live region; a failed submit keeps the text.

**States.** Loading skeleton of both panes. Empty queue: "No findings are waiting for review. New findings appear here after a scan of the default branch." Empty by filter. Error and no-permission. A selected finding that changed under the analyst shows the conflict banner and refreshes. `409 already_decided` removes it from the list with a toast. **A11y:** the list is a listbox with roving focus (`aria-activedescendant`), the panel a labelled region; the queue and panel stack below 1024 px with the panel as a full-screen sheet. **Responsive:** list-only on phones; selecting opens the sheet.

## 8. AiAdvisoryCard (component, used in T-32 and T-34)

**Purpose:** show the false-positive agent's advice as **advice**. **Placement:** T-32 Overview below the location block; T-34 in the review panel above the decision form. **Never** inside the decision form, never preselecting it, never in a status color.

**Fixed identity.** A bordered, neutral card (`--card`, `--border`; **no mint, no severity or status color**), a `sparkles` icon and the title **"AI advisory"**, the always-visible chip **"Advisory — requires a human decision"** and, when ready, the line "Written by a language model. It can be wrong. It never approves, rejects or changes a finding." Provider and model in mono ("ollama · model-name") with the generated time.

| State (`advisory.status`) | Content |
|---|---|
| `none` | "No advice has been requested for this finding." and, for `finding.review` holders, a **Request advice** button (rate limited; disabled with a tooltip while pending) |
| `pending` | "Advice is being prepared." with a quiet spinner (`prefers-reduced-motion` stops it), `aria-busy`; updates through the hint or the 60 s poll; the page never waits for it |
| `ready` | The suggestion as a neutral outlined label with text and icon: **"Likely true positive"** (`shield-alert`), **"Likely false positive"** (`shield-off`) or **"Uncertain"** (`help-circle`) — the icons are the Lucide neutral set, drawn in `--muted-foreground`, not in danger or success colors; **Confidence** "87% (model-reported, not calibrated)" with a plain meter (`role="meter"`, value and text, neutral fill, band word "High") and the band in words for screen readers; **Reasoning** as plain escaped text clamped to 5 lines with "Show more"; footer "Based on: rule, location and a code excerpt" or "Based on: rule and location only" (from `egressLevel`: snippet or metadata; "on this deployment" for local); a **stale** note "Evidence changed since this advice was written" with Request again |
| `failed` | "No advice is available right now. You can continue without it." (calm, neutral, with an `info` icon, never an error style) and Request again |
| `consent_blocked` | "AI advice is turned off for your organization." and, for holders of `tenant_settings.manage`, a link "Review AI settings"; others see only the sentence |
| `not_configured` | "The AI assistant isn't set up for this deployment." |
| secret finding | the `ready` content plus the line "Secret details are never sent to the assistant. This advice uses the rule and file path only." |

**Interactions and a11y.** The card is a `section` with `aria-labelledby`; the suggestion is text first; the confidence meter has a text equivalent; the "Show more" control is a button with `aria-expanded`; the card is never focus-trapped; the agreement or disagreement of the human is not asked. No auto-refresh moves focus. **Copy rules:** never "AI says this is a false positive, so"; never "recommended decision"; the words "advice" and "advisory" only. **Responsive:** single column; the meter and label stack. **Verification** (matrix row below) checks that the card never appears in a status color and never changes any control's state.

## 9. T-35 Approvals queue

**Purpose:** leads approve or reject pending decisions (TP, FP, accepted risk, suppression). **Route:** `/workspaces/:workspaceId/approvals`. **Permission:** `approval.view` to see; approving needs `approval.approve`, rejecting `approval.reject` (without them the sheet shows the evidence read-only with "You can see this queue but not decide").

**Layout.** Header "Approvals" with a count. Filter strip: Decision type (True positive, False positive, Accepted risk, Suppression), Severity, Pipeline, Submitted by, "Waiting more than 3 days". Table: **Finding** (severity badge and title), **Decision** (a neutral outlined chip: "True positive", "False positive", "Accepted risk until <date>", "Suppression"), **Submitted by** (name), **Rationale** preview (two lines, plain text), **Submitted** (relative), **SLA** chip. Row click opens the **right sheet** (the URL keeps `request=<id>`): the finding summary and evidence (shortened viewer), the full rationale or justification and compensating controls, the proposed severity change ("High to Medium"), the expiry for accepted risk, the `AiAdvisoryCard` (read only, as context), the history link, and the buttons **Approve** (mint, primary) and **Reject with comment** (outline; opens a required comment field).

**SOD display.** The rows and the sheet use the server's `canDecide`. When it is false for `separation_of_duties`, both buttons are **disabled with the tooltip** "You recorded a decision on this finding. Another lead must approve it." (for an exception: "You requested this. Another lead must approve it."); the row also carries a small `user-x` icon and the text "Needs another approver" in the Decision cell, so it is never color-only; when false for a missing key the buttons are hidden. A confirmation dialog follows every approve and reject ("Approve this true positive? The finding will be confirmed and can then be assigned."). An approver who is also the only eligible person sees the note "No other approver is available for this request" (SOD-6) on their own items.

**States.** Loading skeleton; empty: "Nothing is waiting for approval."; empty by filter; error; no-permission; 409 shows "This request was already decided or the finding changed" and removes it. After a decision: toast, the row disappears with a polite announcement, focus moves to the next row. **A11y:** table pattern as T-31; the sheet is a dialog region with focus management and `Escape`; tooltips on disabled buttons are reachable by keyboard (the button is `aria-disabled` and focusable, not `disabled`). **Responsive:** the sheet becomes a full-screen view below 1024 px; the table becomes cards below 768 px.

## 10. T-36 Remediation board

**Purpose:** developers and dev leads see and move remediation work. **Route:** `/workspaces/:workspaceId/remediation`. **Permission:** `remediation.view`; moving cards needs `finding.remediate` (own cards unless the user also holds `finding.assign`); assigning needs `finding.assign`.

**Layout.** Header "Remediation" with a Board / Table toggle (URL `view`), filters (Assignee incl. "Me", Severity, Pipeline, SLA). **Board columns** (five, SPEC C-3): **Assigned**, **In progress**, **Fixed, pending verification**, **Verified fixed** (last 30 days), **Reopened**. Column header: name, count, and for "Fixed, pending verification" the note "Verified by the next complete scan." Cards: severity badge, title (two lines), repository name, assignee avatar, SLA chip, the PR link text and ticket key when present, the recurrence icon on Reopened. Each column loads 25 and has "Load more". **Card data (owner decision 2026-11-24, SPEC 0.5 OD-10):** the board card is the list item plus `canRemediate` (server-computed for the caller), and the optional, nullable `pullRequestUrl` and `ticketKey` of the latest submitted fix (shown as text with a safe link and as plain text); they are absent from every other DTO. The Table view reuses the T-31 table limited to remediation statuses.

**Drag rules vs permissions** (the server decides; the UI only mirrors `allowedActions`):

| Move | Allowed for | Result |
|---|---|---|
| Assigned to In progress | the assignee, or a holder of `finding.remediate` and `finding.assign` | SM-12 |
| Assigned or In progress to Fixed, pending verification | same | opens the Submit fix dialog first (PR URL, ticket key, note), then SM-13 |
| Reopened to Assigned | `finding.assign` (opens the assignee picker) | SM-17 |
| any move into **Verified fixed** or **Reopened**, or out of Fixed, pending verification | **nobody**: these columns are system-driven | the drop target is marked "Set by scans" and refuses the drop with the live message "Only a complete scan can verify or reopen a finding." |
| any other move | nobody | refused with the reason |

An unauthorized card is not draggable (no drag handle, `aria-disabled`), with the tooltip "You can only move findings assigned to you" or "You need permission to assign findings".

**Keyboard alternative (required).** Every card has a **"Move to"** menu button (and `M` when focused) listing only the allowed target columns, which runs the same action and dialogs as dragging; arrow keys move focus between cards and columns; `Enter` opens T-32; a live region announces "Moved to In progress". Drag and drop is an enhancement, never the only path.

**States.** Loading skeleton columns; empty board: "No remediation work yet. Findings appear here after a lead assigns them."; empty by filter; empty column text "Nothing here"; error; no-permission. A rejected move snaps the card back with a toast stating the reason. Realtime moves cards from other users with a brief outline (no animation under reduced motion). **A11y:** columns are labelled lists; counts in the column labels; the drag uses a pointer-events implementation with a keyboard-equivalent menu (no new dependency without a justification, SPEC 13); color is never the only signal. **Responsive:** columns scroll horizontally inside the board region (the page does not scroll sideways); below 768 px the board becomes a column selector (tabs) showing one column at a time.

## 11. Settings additions (small, Recommended)

- **Findings SLA targets** (tenant Settings, section "Findings"): a four-row form (Critical, High, Medium, Low; Info "No SLA"), hours or days selector, "Reset to defaults", Save (`tenant_settings.manage`); read-only for `tenant_settings.view`; helper "Changes apply from the next recalculation; overdue findings stay overdue."
- **Code-excerpt consent** (the existing AI assistant card of scan-decisioning SCREENS 3b): a second switch "Send short code excerpts of findings to the external model provider", off by default, enabled only when the first switch is on, with the stronger text "Short excerpts of your source code (never secrets) would leave your deployment when the AI advisory runs with an external provider. A local model needs no consent." Same audit and confirmation dialog as the first switch.

## 12. Accessibility summary

WCAG 2.2 AA targets: all screens keyboard operable; visible focus ring (mint); tables, tabs, listboxes, dialogs and sheets follow the ARIA patterns; severity, status, SLA and advisory state always carry text and an icon; live regions for queue progress, moves, decisions and realtime changes (polite); `prefers-reduced-motion` honored; contrast per DESIGN_SYSTEM section 5 (light-theme derived severity variants); touch targets at least 40 px on touch layouts; no content depends on hover only (tooltips also appear on focus).

## 13. Verification matrix (to be run by hand after implementation; nothing is claimed)

Roles: **Analyst** (finding.review), **Lead** (approve), **Dev Lead** (assign), **Developer** (remediate own), **Admin**, **Viewer**, **No access / other workspace**.

| Screen or behavior | Analyst | Lead | Dev Lead | Developer | Admin | Viewer | Other workspace or tenant |
|---|---|---|---|---|---|---|---|
| T-31 list, filters, views, pager | yes | yes | yes | yes, default "Assigned to me" | yes | yes read-only | not found |
| T-31 bulk Start review | yes | hidden | hidden | hidden | yes | hidden | n/a |
| T-31 bulk Assign | hidden | hidden | yes | hidden | yes | hidden | n/a |
| T-32 view, evidence, history | yes | yes | yes | yes | yes | yes | not found |
| T-32 Record decision / Start review | yes | hidden | hidden | hidden | yes | hidden | n/a |
| T-32 Approve, Reject | hidden | enabled, **disabled with tooltip on own review** | hidden | hidden | hidden by default | hidden | n/a |
| T-32 Assign, Unassign | hidden | hidden | yes | hidden | yes | hidden | n/a |
| T-32 Start work, Submit fix | hidden | hidden | yes | **only own assignments** | yes | hidden | n/a |
| T-33 request (accept risk / suppression) | per bundle (SPEC 3.2) | yes | per bundle | hidden | yes | hidden | n/a |
| T-34 queue and decision form | yes | page yes, form hidden | hidden page | hidden page | yes | hidden page | not found |
| T-35 queue and decide | hidden | yes (SOD tooltip) | hidden | hidden | read-only | hidden | not found |
| T-36 board view and moves | read | read | all moves | own cards | all | hidden page | not found |
| AiAdvisoryCard states (none, pending, ready, failed, consent_blocked, not_configured, secret) | each | each | each | each | link to settings visible | each | n/a |

Behavior rows to run: loading, empty, empty-by-filter, error with correlation id and no-permission on every screen; a `409` while editing keeps the typed text; SOD tooltip reachable by keyboard; `credential_shape` refusal on rationale, comment and justification; evidence viewer for SAST block, SCA component, secret masked line (no copy button), no evidence, truncated, purged; commit-pinned link opens the exact commit (live, LT-F5); every severity and status readable in grayscale; board keyboard "Move to" for every allowed move and refusal text for system-only columns; advisory card never colored as a status and never preselects the decision; narrow-width layouts of all six screens; light and dark themes; screen reader pass (LT-F6); realtime update of a status without losing focus; 100,000-finding list scrolls by pages without freezing.

## 14. Open points for the owner

| # | Point | Recommendation |
|---|---|---|
| S-1 | Nav label "Security Reviews" vs "Reviews" (SPEC C-2) | keep "Security Reviews" (WF, design docs); the screen title is "Reviews" |
| S-2 | FP needs approval (SPEC OQ-3) | yes; the Approvals queue then shows FP decisions |
| S-3 | Board drag-and-drop without a new dependency | pointer events plus the "Move to" menu; adding a library needs justification |
| S-4 | Confidence displayed as a number | yes, with the "model-reported, not calibrated" caption and the band word |
| S-5 | Counts in the nav | Findings, Security Reviews, Approvals only (design rule) |
