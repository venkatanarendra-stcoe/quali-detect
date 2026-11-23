# Findings, Part E, UI: as built

**Built:** 2026-11-23 on `8b0ac85` (A0 contract freeze), worktree branch `worktree-agent-a00095ca348e20685`, not pushed. **Status:** Wave 1, the UI runs against an in-repo mock; no API route of the module exists yet, so nothing here has met the real backend. This part writes its notes **only here** (`SPEC.md` 16.4); Part F folds them into `SPEC.md` 17 and the progress tracker.

**Owned and changed:** `apps/tenant-web/src/features/findings/**` (new), the findings block of `apps/tenant-web/src/app/routes.jsx`, the four `implemented` flags in `packages/shared/src/navigation.js`, one segment in `apps/tenant-web/src/components/layout/nav.js` (see 4), this file. No dependency added, no TypeScript, no edit of `apps/api`, `packages/db`, other `packages/shared/src/findings` files, SPEC or ADR files. `expected.js` is untouched: the spec assigns Part E no suite checks.

## 1. What was built

Feature folder `apps/tenant-web/src/features/findings/` (`components/ pages/ hooks/ services/ schemas/ stores/ constants/ index.js`).

| Screen | Route (workspace-nested) | Route key | Files |
|---|---|---|---|
| T-31 Findings list | `/workspaces/:id/findings` | `finding.view` | `pages/findings-page.jsx`, `components/findings-list.jsx`, `findings-table.jsx`, `findings-filters.jsx`, `bulk-bar.jsx` |
| T-32 Finding detail | `/workspaces/:id/findings/:findingId` | `finding.view` | `pages/finding-detail-page.jsx`, `finding-overview.jsx`, `finding-history.jsx`, `finding-actions.jsx`, `code-viewer.jsx` |
| T-33 Accept-risk and suppression dialog | dialog on T-32 | `finding.accept_risk` / `finding.suppress` (menu item hidden without the key, from `allowedActions`) | `components/exception-dialog.jsx` |
| T-34 Reviews queue | `/workspaces/:id/reviews` | `security_review.view` | `pages/reviews-page.jsx`, `components/review-queue.jsx`, `decision-form.jsx` |
| T-35 Approvals queue | `/workspaces/:id/approvals` | `approval.view` | `pages/approvals-page.jsx`, `components/approvals-queue.jsx` |
| T-36 Remediation board | `/workspaces/:id/remediation` | `remediation.view` | `pages/remediation-page.jsx`, `components/remediation-board.jsx` |
| `AiAdvisoryCard` | inside T-32, T-34, T-35 sheet | follows the host | `components/ai-advisory-card.jsx` |

Shared pieces: `finding-bits.jsx` (SeverityBadge, StatusBadge, SlaChip, RecurrenceIcon, AdvisoryHint, Person, LocationCell, Untrusted), `form-bits.jsx` (Field with live counter and `aria-describedby`, ConflictBanner), `action-dialogs.jsx` (decision, approve and reject, assign, submit fix, assignee picker), `hooks/use-findings.js` (keys, queries, the generic write mutation, `describeActionError`), `schemas/filters.js` (URL to query), `schemas/forms.js` (React Hook Form schemas mirroring the frozen request schemas), `schemas/validate.js` (a Zod refusal becomes the same `ApiError` the server answers), `stores/findings-ui-store.js` (selection capped at 50, shortcut switch).

**Rules kept.** Every permission decision is `useCan()` (the central engine) or the server's `lifecycle.allowedActions` / `canDecide` / `canRemediate`; no role name appears. An action absent from `allowedActions` is hidden; present with `allowed: false` it is shown disabled with the server's `disabledReason`, in a focusable `aria-disabled` wrapper so the tooltip is reachable by keyboard (SOD on Approve and Reject, on T-32 and T-35). Untrusted text (titles, rationales, snippets, comments, model reasoning, PR URL when not https) is React text, never HTML or Markdown. Severity is a tint pill with icon and label; status is an outlined chip with icon and label; SLA chip text carries the state word (visible text plus a screen-reader prefix). Mint appears only on the primary button, the active navigation item and the focus ring; `AiAdvisoryCard` uses `--card`, `--border` and neutral foregrounds only (checked: no primary, severity or status class inside it). Mono is used only for identifiers (fingerprint, rule id, path, component, commit, model, code).

**AiAdvisoryCard.** States `none`, `pending` (`aria-busy`, spinner stops under reduced motion), `ready`, `failed` (calm, info icon), `consent_blocked` (link "Review AI settings" only with `tenant_settings.manage`), `not_configured`, secret finding. Always the chip "Advisory — requires a human decision"; `ready` adds the model line, the suggestion as a neutral outlined label with a Lucide icon in the muted colour, confidence with a `role="meter"` (value, band word, `aria-valuetext`, "model-reported, not calibrated"), reasoning clamped to 5 lines with a "Show more" button (`aria-expanded`), the "Based on" line from `egressLevel`, the stale note with "Request again". It is rendered outside the decision form and never changes a control. **Owner decision OD-3 wins over the SCREENS table row "secret finding": a secret finding never gets advice, so the card says so in words and offers no button.**

**Evidence.** SAST: the enclosing block with line numbers, focus lines marked by tint, a left bar and screen-reader text ("highlighted line 41", caption "highlighted lines 41 to 42"), a keyboard-focusable scroll region, "Wrap lines" toggle, copy button. Secret: the masked line preview, `[line withheld]` rendered as a muted marker with a screen-reader explanation, "The value is never stored. Rotate it if it is real.", **no copy button**. SCA: component, ecosystem, fixed versions, advisories as a data list. The commit-pinned link ("View at commit a1b2c3d on GitHub", new tab, `rel="noopener noreferrer"`, only when the DTO `link.url` is `https`, else "No link available"). Truncated, purged and missing excerpts have their sentences.

**List.** Saved-view tabs with summary counts, search (`/` focuses it), a left facet panel (collapsible from 1280 px, a sheet below 1024 px), removable chips with "Clear all", sortable header with `aria-sort`, numbered pager (25, 50, 100) with the total only in the pager, selection with a live count, bulk Start review and Assign capped at 50 with the eligibility sentence and a per-finding result dialog, a card list below 768 px. **Board:** five columns, "Load more" per column, native HTML drag and drop only where `canRemediate` allows (card `draggable`, grip icon), "Move to" menu on every card (and `M` on a focused card), arrow keys between cards and columns, Submit fix and Assign dialogs opened first, system columns marked "Set by scans" with the refusal "Only a complete scan can verify or reopen a finding.", a live region for each move, a column selector (tabs) below 768 px, a Table view reusing the list table. **Reviews:** split view (listbox with `aria-activedescendant`), the decision form never preselected, keys `J K T F R Ctrl+Enter` (off while typing, switchable), submit selects the next finding and announces it, a full-screen sheet below 1024 px. **Approvals:** table, right sheet (`request` in the URL), Approve and Reject confirmations, Reject needs a comment, cards below 768 px.

## 2. The mock layer (no dependency)

`services/findings-service.js` exports `findingsApi` (the real calls) and `findingsService`, which is `findingsApi` unless `VITE_FINDINGS_MOCK=true` in a **development** build (`import.meta.env.PROD` forces it off, so a production bundle can never use the mock). `services/findings-api.mock.js` implements the same function names in memory: the frozen state machine (`isTransitionAllowed`), the frozen request schemas (`parseOrApiError`), caller permissions through the central `can`, per-caller `allowedActions`, `canDecide`, `canRemediate`, SOD, `rev` conflicts (`FINDING_STATE_CONFLICT` with `details.reason`), bulk results, and **parses every response with the frozen DTO schemas** (a mismatch throws: this caught one defect of the mock itself, an evidence `kind` longer than the schema allows). `services/findings-mock-data.js` builds 60 deterministic findings (SCA, SAST, secrets; every status; advisory in every state; evidence variants: block, component, masked line, none, purged, truncated, no link, `[line withheld]`; deleted pipeline; reopened; pending exceptions; some reviews and assignments owned by the signed-in user so SOD and "own cards" show). Failure modes for checks: `sessionStorage["qm-findings-mock"]` = `empty`, `error`, `forbidden`, `notfound`, `slow`.

Start the app on the mock: `VITE_FINDINGS_MOCK=true pnpm --filter @qmentisai/tenant-web dev` (the rest of the shell still needs the real session endpoints or a stub for `GET /me`).

## 3. Mock to real mapping (Wave 3: turn the flag off)

Every `findingsApi` function sends the request body through the frozen shared schema first and an `Idempotency-Key` on every write; collection reads use `getPage` (`{ items, pagination }`).

| UI call (`findingsService.*`) | Real endpoint | Needs from the backend |
|---|---|---|
| `list` | `GET /findings?workspaceId=&view&severity&status&scanType&pipelineId&repositoryId&assignee&sla&aiSuggestion&q&sort&direction&page&pageSize` | the UI drops `view` when a `status` filter is set (so closed statuses can be listed) |
| `summary` | `GET /findings/summary?workspaceId=` | |
| `get` | `GET /findings/{id}` | `lifecycle.allowedActions`, `rev`, `advisory` |
| `history`, `comments` | `GET /findings/{id}/history`, `/comments` (`cursor`, `limit`; `meta.pagination.nextCursor`) | |
| `similar` | `GET /findings/{id}/similar` | |
| `reviewQueue` | `GET /review-queue` | |
| `approvals` | `GET /approvals` | `canDecide`, `cannotDecideReason` |
| `board`, `boardColumn` | `GET /remediation/board`, `/remediation/board/{column}` (`cursor`, `limit`) | `canRemediate` per card |
| `claim` | `POST /findings/{id}/claim` | |
| `createReview` | `POST /findings/{id}/reviews` | |
| `withdrawReview` / `approveReview` / `rejectReview` | `POST /findings/{id}/reviews/{reviewId}/withdraw` / `approve` / `reject` | |
| `reopenReview` | `POST /findings/{id}/reopen-review` | |
| `assign`, `clearAssignment` | `POST /findings/{id}/assignments`, `/assignments/clear` | |
| `startRemediation`, `submitRemediation` | `POST /findings/{id}/remediation/start`, `/submit` | |
| `createException`, `withdrawException`, `approveException`, `rejectException`, `revokeException` | `POST /findings/{id}/exceptions` and `/{exceptionId}/withdraw`, `/approve`, `/reject`, `/revoke` | |
| `addComment` | `POST /findings/{id}/comments` | |
| `requestAdvisory` | `POST /findings/{id}/advisory/request` (202, `429` handled as a sentence) | |
| `bulkClaim`, `bulkAssign` | `POST /findings/bulk/claim`, `/bulk/assign` | |
| `slaSettings`, `putSlaSettings` | `GET`/`PUT /settings/findings-sla` | functions exist, **no screen yet** (see 5) |
| `pipelines` (filter options) | `GET /pipelines?workspaceId=&limit=100` (existing; needs `pipeline.view`, empty options without it) | |
| `assignees` (picker) | `GET /workspaces/{id}/members` (existing; the server still refuses an ineligible assignee with `assignee_not_eligible`) | |

Query keys: `["tenant", tenantId, "workspace", workspaceId, "findings", ...]`. Refresh: every screen polls every 60 s and refetches on focus (the realtime room is Part B); the detail polls every 5 s while the advisory is `pending`.

## 4. Deviations from `SCREENS.md` / `SPEC.md` and why

1. **Route `/findings/:findingId` (alias without a workspace) is not built.** It needs the workspace from `GET /findings/{id}`, but SPEC 8.3 forbids `workspaceId` in the finding DTO. Report to the integrator: either allow `workspaceId` in the detail DTO or drop the alias. Same-workspace links work.
2. **Nav segment.** `nav.js` mapped "Security reviews" to `/security-reviews`; SCREENS 3 says `/reviews`, so the segment is `reviews` (label unchanged, S-1). `isRouteAvailable` and `SECTION_ITEM` follow the route table.
3. **Nav counts (SCREENS 3, S-5) are not shown.** Recommended, not Confirmed; needs a sidebar edit outside this part's files. The counts exist in `GET /findings/summary` and the list tabs show them.
4. **Settings additions (SCREENS 11: SLA targets section, code-excerpt consent second switch) are not built.** The task scoped Part E to T-31 to T-36 and the card; `putSlaSettings` / `slaSettings` exist in the service. The consent switch also needs Part D's field.
5. **No `defaultView` from the summary** (the strict summary schema has none). The default tab is "Assigned to me" when `useCan` says the caller can remediate and cannot review, otherwise "All open": a permission decision, not a role name.
6. **Pagination URL parameter is `limit`, not `pageSize`** (the repo's `useListParams` convention); the API call sends `pageSize`.
7. **Row keys.** Rows are focusable and Enter opens them (the shared `DataTable`); arrow-key roving between rows and Space-to-select are not built (Space opens the row). The checkbox column is a normal tab stop.
8. **Approvals filters.** The frozen query accepts `kind` (decisions or exceptions), severity and pipeline only: no separate true / false / accepted risk / suppression filter, no "Submitted by", no "Waiting more than 3 days". The sheet cannot show compensating controls (the exception DTO has none). The "No other approver is available" note (SOD-6) needs a server flag and is not shown.
9. **Reviews filters "Mine" and "Unclaimed"** are applied to the loaded page (the frozen queue query has no such filter), so with several pages the pager total is for the unfiltered queue.
10. **Board cards** carry no PR link or ticket key (the card DTO is the list item plus `canRemediate`); they are on T-32. Drag uses native HTML5 drag and drop, not pointer events (SCREENS S-3 allowed either, no dependency); touch devices use "Move to". The "recently moved by others" outline is not built (no realtime).
11. **Comments tab label** is "Comments (n)" with `n` the loaded count and a "+" when more exist (no count in the DTO).
12. **Evidence kind** of a secret is `line` in the mock (the schema allows at most 10 characters; the SPEC names no value).
13. **Credential-shape check** runs in the form (shared `hasCredentialShape`) and again in the service; the server's refusal maps to the same message and field.

## 5. Verified, and not verified

**Verified by running** (headless Chrome 1440, 900, 820 and 390 px wide, light and dark, against the mock and a scratch session API that only answers `GET /me` and workspaces; personas = the built-in roles Admin, Security Lead, Security Analyst, Dev Lead, Developer, Viewer): T-31 list (default sort and `aria-sort`, filters round trip in the URL, chips, Clear filters, search with `/`, numbered pager and page size, saved-view tabs and counts, selection, bulk Start review result dialog, 50 cap toast, eligibility sentences, loading, empty, empty by filter, error with reference, forbidden, card list at 390, filter sheet); T-32 (every advisory state, SAST block, SCA data, masked secret without copy button, `[line withheld]`, no excerpt, purged, truncated, no link, commit link attributes, tabs by URL and by arrow key, history, comments, composer hidden for a viewer, not found, one `h1`, no horizontal page scroll at 390 and 820); actions (Start review, decision form validation, **credential refusal keeps the typed text and marks the field**, submit, status and history update, approve confirmation, **SOD disabled Approve and Reject with the tooltip reachable by Tab**, exception dialog with presets and range errors, pending-exception banner, suppression variant, full-screen dialog at 390, assign with picker, Start work, Submit fix with https validation, "Fixed, pending verification" never shown as verified, PR link `rel`); T-34 (listbox, panel, advisory above and outside the form, nothing preselected, `J K T F R Ctrl+Enter`, no shortcut while typing, next finding selected and announced, filters, empty, error, sheet at 390, Dev Lead and Viewer denied); T-35 (rows, SOD rows with icon and words, sheet, reject needs a comment, approve confirmation, row leaves with an announcement, admin read-only note, analyst denied, kind filter, empty, forbidden, cards at 390); T-36 (five columns and counts, drag to In progress, refusal into Verified fixed with message, Submit fix first for Fixed, pending, `M` menu with only the allowed targets, arrow keys across cards and columns, Reopened to Assigned opens the assign dialog, system cards have no menu, developer sees only own cards movable with the reason on the others, Table view, column tabs at 390, empty, error, loading); navigation (the four items appear by permission, none for a viewer on Reviews and Approvals).

**Not verified:** any run against the real API (none of the routes exists; Wave 3); the 409 flow beyond the mock (`stale_revision` banner copy checked in code only); realtime (none built); a screen reader (no human or assistive-technology pass: LT-F6 stays open); contrast measurements (tokens only, light and dark eyeballed in screenshots); `prefers-reduced-motion` by eye (the spinner and drag classes use `motion-reduce`, the emulation flag was not exercised); touch drag; 100,000-finding list behaviour (pages of 25 to 100 only, no virtualization needed, not measured); browsers other than Chrome; the dark theme of every dialog; the keyboard path through every dialog (focus trap and Escape come from Radix; first-field focus was not checked in every dialog); the consent card second switch and SLA settings (not built); the commit link opening the exact commit on GitHub (LT-F5, needs live data); the grayscale reading of severity and status (every one carries icon and text, not checked in a grayscale render).

## 6. Open points for the integrator

- Allow or drop the unscoped alias route (deviation 1).
- `workspaceId` is not in any finding DTO; list calls pass it as a query parameter and item routes derive it, as SPEC 8 says, so the UI never needs it from a DTO except for that alias.
- The card DTO for the board has no PR link or ticket key; add them to the card if the board should show them (SCREENS 10 lists them).
- Part B: `canDecide` and `cannotDecideReason` must be computed per request for the board and queue exactly as the mock does, and `lifecycle.allowedActions` must hide an action the caller can never perform and disable one it may request, with `disabledReason` in words, or the buttons will be wrong.
