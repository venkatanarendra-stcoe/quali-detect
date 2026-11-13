# QmentisAI UX Guidelines

**Status:** Final — revision 3 (Obsidian / Electric Mint palette, Geist Sans + Geist Mono, Tailwind CSS v4, approved Tenant dashboard reference). Frontend implementation started 2026-11-11 (tenant app foundation).

The approved visual reference is the Tenant dashboard (`DESIGN_SYSTEM.md` §9). Status labels, icons and tones are defined once in `DESIGN_SYSTEM.md` §10; do not redefine them per module.
**Companion:** `DESIGN_SYSTEM.md` (tokens, components, contrast). This document covers behavior, layout and interaction. It applies to both the Tenant Application and the Root Console.

Permissions shown in screen specs are indicative until a role-permission matrix exists. The UI may hide or disable actions; the backend enforces every protected action.

---

## 1. Principles

1. **Quiet by default, loud on meaning.** Neutral surfaces; color appears only for severity, status, the primary action and the active location.
2. **Data first.** Tables and summaries lead; chrome stays thin. Prefer density over whitespace on data screens.
3. **One primary action per view.** It is the only mint-filled button.
4. **Predictable.** Same header, same filter bar, same row actions, same dialogs on every module.
5. **Honest about certainty.** AI output is labeled advisory; human decisions are labeled as decisions; a finding is never shown as fixed unless verified by a scan that covers it.
6. **Safe by design.** Destructive, audited, or cross-tenant actions require explicit confirmation and show their scope.

---

## 2. Mint usage rules (UX view)

Mint (`--primary`) may appear as: the primary button, the active nav item, the focus ring, selected controls, in-text links, and **one** highlighted item per page. It must not appear on decorative icons, borders, dividers, card headers, status or severity indicators.

Checklist before shipping a screen:
- Exactly one mint-filled button visible.
- Mint total is limited to nav indicator, focus ring, and ≤ 2 other elements.
- Severity and status are legible in grayscale (icon and text present).
- Light theme uses `--primary-text` for small mint text.

---

## 3. Layout standards

### 3.1 Application shell

| Region | Spec |
|---|---|
| Sidebar | 240 px, collapsible to 56 px (icons with tooltips). Background `--sidebar`, 1 px right border. Sections with 11 px uppercase labels in `--subtle-foreground`. |
| Top bar | 48 px, `--background`, 1 px bottom border. Left: breadcrumb or workspace switcher (Tenant app only). Right: global search (⌘K / Ctrl+K), notifications, theme toggle (Light / Dark / System), user menu. |
| Content | Max width fluid; padding 24 px. Content scrolls; sidebar and top bar are fixed. |
| Page header | Breadcrumb, title (20/28), optional status chip, secondary actions, then the primary action at the far right. |

### 3.2 Page templates

1. **Overview**: metric row (4–6 tiles) → primary chart row → tables/lists. Summary before detail.
2. **List**: page header → filter bar → data table → pagination.
3. **Detail**: page header with status → tab bar → two-column body (main + 320 px side panel for metadata and actions).
4. **Wizard/Form**: single column, max 640 px, sticky footer with Cancel / Back / Primary.
5. **Queue (split view)**: list on the left (360 px), detail on the right.

### 3.3 Responsiveness

Desktop first (≥ 1280 px). At 768–1279 px the sidebar collapses to icons and side panels move below content. Below 768 px the sidebar becomes a drawer and tables reflow into stacked rows showing severity, title, status and one action. Horizontal page scroll is never acceptable; wide tables scroll inside their own container.

---

## 4. Navigation

### 4.1 Tenant Application

Grouped per `FEATURE_CATALOG.md`:

- **Overview**: Overview
- **Engineering**: Workspaces, Repositories, Pipelines, Executions, Scan History
- **Security**: Findings, Security Reviews, Approvals, Remediation, Policies, Reports
- **Administration**: Users, Groups, Roles & Permissions, Integrations, Audit Logs
- **Settings**: Settings (Organization, Account, Authentication & SSO, Notifications, API & Developer, Usage & Consumption, Data Governance)

### 4.2 Root Console

- **Platform**: Platform Dashboard, System Monitoring
- **Customers**: Tenant Management, Subscription Management, License Management, Feature Entitlements, Usage & Quotas
- **Platform administration**: Platform Users, Integration Catalog, Global Configuration
- **Operations**: Support & Diagnostics, Platform Audit Logs

### 4.3 Rules

- Active item: `--sidebar-active-bg` background, `--sidebar-active-foreground` text and a 2 px mint indicator on the left edge. Inactive icons use `--muted-foreground`.
- Hide nav items the user cannot access; show a deliberate unauthorized state if they reach the URL.
- Items carry count badges only when counts require action (for example pending approvals), in neutral style.
- Breadcrumbs reflect the hierarchy Tenant → Workspace → Repository → Pipeline → Execution; every segment is a link.
- Filters, sort, pagination and selected tab are stored in URL search params so views are shareable.
- Tenant workspace switcher scopes data. The current scope is always visible. The Root Console shows a "PLATFORM" tag instead.

### 4.4 Terminology

Use the glossary exactly (Tenant, Workspace, Repository, Pipeline, Execution, Finding, Fingerprint, Accepted Risk, Suppression, Entitlement, Quota). Roles use the names in `PROJECT_CONTEXT.md` (Admin, Manager, Lead, Security Analyst, Dev Lead, Developer, Guest / Viewer). Workflow labels: **Security Review** (analyst TP/FP decision) and **Approval** (Lead approve/reject). Avoid "Security Team" as a UI label.

---

## 5. Tables, filters and lists

- Filter bar above the table: search, 2–4 primary filters (severity, status, workspace/pipeline, assignee/date), a "More filters" popover, and a "Clear all" link. Active filters show as removable chips.
- Saved views are a later enhancement; design the bar so they can be added.
- Columns: severity first for findings, then the title, then context columns, with the row action menu (kebab) last. Column visibility and density (comfortable 36 px / compact 32 px) are user preferences.
- Sort indicators on sortable headers; default sort is explicit and visible.
- Pagination: cursor-based with page size 25/50/100. Show total only where cheap.
- Row click opens a right-side **drawer** for a quick look; a "Open full page" link goes to the detail page. Rows are keyboard focusable.
- Bulk actions: a selection bar replaces the filter bar when rows are selected ("12 selected" + actions + Clear).
- Long identifiers (fingerprint, SHA, path) use the mono font, truncated in the middle with a copy button and full value in a tooltip.

---

## 6. Forms, dialogs, drawers, tabs

- **Forms**: labels above inputs; required marked in the label; helper text under the field; validation inline on blur and again on submit; the first invalid field receives focus. Zod schemas back the validation messages.
- **Dialogs**: only for confirmation or short (≤ 3 fields) input. Title states the action; the body states the effect and scope; buttons are verbs ("Suspend tenant", not "OK").
- **Typed confirmation**: required for tenant suspension/deactivation, credential revocation, deleting a workspace. The user types the resource name.
- **Reason required**: TP/FP decision, approve/reject, accepted risk, suppression, and platform support access each require a recorded reason (audited).
- **Drawers**: for previews and secondary editing; width 480 px (640 px for evidence). Escape closes; focus returns to the originating row.
- **Tabs**: for sub-sections of one entity (Overview, Evidence, History, Comments). Tab state lives in the URL. Do not nest tabs.
- **Toasts** (Sonner): confirm completed actions in one line; errors that need action stay in the page, not in a toast.

---

## 7. Severity, status and provenance

- **Severity** (Critical, High, Medium, Low, Info) is a tinted pill with icon and label. Sorting always orders Critical → Info.
- **Status** is an outlined chip with icon and label. Proposed finding lifecycle labels (**Recommended**, pending the Findings module spec): New, In Review, Confirmed (TP), False Positive, Pending Approval, Assigned, In Remediation, Awaiting Verification, Fixed (verified), Accepted Risk, Suppressed. Pipeline and execution states: Queued, Running, Succeeded, Failed, Cancelling, Cancelled.
- A finding shows **Fixed** only after verification; absence from an incremental scan displays as "Not observed in latest incremental scan" and does not change status.
- AI-generated content carries a `ProvenanceTag` and a confidence/evidence reference. Human decisions show actor, time and reason. AI output is never styled like a final decision.
- Cross-pipeline similarity is shown as a "Related findings" list with links. Findings from different pipelines are never visually merged into one record.
- Secrets in evidence render redacted with a label; they are never selectable or copyable.

---

## 8. Required states

Every data view implements all of the following. Use the shared components.

| State | Behavior |
|---|---|
| **Loading** | Skeleton matching the final layout; no spinner-only pages. Tables show 8 skeleton rows. |
| **Empty (no data)** | Icon, one sentence on what belongs here, and the primary action if the user may create. |
| **Empty (no results)** | "No results match these filters" with Clear filters. |
| **Error** | Plain-language message, Retry, and the correlation ID (copyable). No stack traces or internal details. |
| **Unauthorized** | Explains missing access and whom to ask; no data leaks, no broken layout. |
| **Success** | Inline confirmation or toast; the changed row/status updates in place. |
| **Partial / degraded** | Banner when an integration or worker is unhealthy; stale-data timestamp when real-time is disconnected. |
| **Long-running** | Progress with elapsed time, cancel where allowed, and a way to leave and return. |

Real-time (Socket.IO) updates patch existing rows and show a subtle "updated" cue, never reorder rows under the cursor unexpectedly.

---

## 9. Charts and data visualization

- Recharts with tokens from `DESIGN_SYSTEM.md` §2.4. Severity charts use severity tokens, in the fixed order Critical → Info.
- Mint appears only on the primary series. Add direct labels or a legend; do not rely on color alone.
- Gridlines faint (`--chart-grid`), axes in `--subtle-foreground`, tabular numerals for tick labels.
- Every chart has an accessible text alternative (a summary line or a data table toggle) and a loading/empty/error state.
- Prefer sparklines and small multiples over large decorative charts. No 3D, no gradients.

---

## 10. Accessibility

- Contrast requirements and measured ratios are in `DESIGN_SYSTEM.md` §5. Design to those; do not substitute a supplied color where the doc names a derived variant.
- Full keyboard operation: logical tab order, skip-to-content link, arrow-key navigation in menus and tables where applicable, Escape closes overlays, focus is trapped in dialogs and restored on close.
- Focus ring is always visible (2 px mint in dark, `#087F70` in light).
- Icon-only buttons have `aria-label` and tooltips. Tables use proper header semantics. Live updates use `aria-live="polite"`.
- Respect `prefers-reduced-motion` and `prefers-color-scheme`; support text zoom to 200 % without loss of function.
- Time values use relative text with the absolute timestamp in a tooltip (date-fns), in the user's time zone.

---

## 11. Content and tone

Plain, specific, active voice. Buttons are verbs. Errors say what happened and what to do. Avoid alarmist language; severity is expressed by the severity component, not by exclamation marks. Use real units and terms from the domain (CVE, CWE, SHA, fingerprint, SLA) without explaining them in primary UI; explain in tooltips.

---

## 12. Do / Don't

| Do | Don't |
|---|---|
| Use neutral surfaces and let severity carry color | Tint surfaces with brand color |
| One mint primary button | Several mint buttons or mint icons across a page |
| Borders and tonal steps for hierarchy | Heavy shadows, glows or gradients |
| Dense, aligned tables | Large cards around every table |
| Confirm destructive and audited actions | Single-click irreversible changes |
| Reuse shared components | Build a second badge/table/dialog for one screen |
| Show AI output as advisory with provenance | Present AI output as a decision |

---

## 13. Wizard layout

Multi-step flows (T-23, T-26, R-05, and the horizontal `Stepper` of Create workspace) use `WizardLayout` and `Stepper` from `@qmentisai/ui` (no router or app imports; the app passes an `offset`, the height of the chrome above the page, default 6 rem; the Root Console passes 7.5 rem).

- The wizard fills the viewport below the app chrome (at least 32 rem): **the page never scrolls**. The title and description are fixed at the top; the stepper (left) and summary (right, from 1280 px) stay put; **only the form column scrolls**. The action bar (Cancel left; Back / Next / Create right; top border) sits under the form and is always visible. `scroll-padding-bottom` and `scroll-margin-bottom` keep focused fields clear of it.
- Below 1280 px the summary becomes a disclosure above the form (button with `aria-expanded` and `aria-controls`); below 1024 px the stepper is a horizontal indicator that scrolls sideways and keeps the current step in view.
- Stepper: one list; the current step has `aria-current="step"`; completed and error steps carry an icon AND text ("(completed)", "(needs attention)"), never colour alone; steps are buttons when navigation is allowed. Tab order: summary disclosure (when shown), stepper, form, action bar.
- Validate the whole draft with the schemas the API uses; keep the final action disabled until it is valid and list problems with a "Fix in <step>" link. One empty-value glyph: the em dash.

---

## 14. Shared form, layout and table primitives (`@qmentisai/ui`)

Tenant Application primitives; the Root Console is unaffected unless it imports them. Colours come from existing tokens only (focus ring `--ring`; no brand fill on these controls).

- **`Combobox` / `MultiSelect`** replace native `<select>`. ARIA 1.2 combobox with `aria-activedescendant`; the listbox is rendered in a portal (position fixed, flips above when there is no room) so cards and `overflow-hidden` ancestors never clip it. Keys: arrows, Home/End, Enter, Escape (closes without closing an enclosing dialog), Tab, type-ahead (non-searchable), Backspace removes the last chip. Static `options`, local search, or async `loadOptions(query, { signal })` (debounced, loading / empty / error with Retry). Forwards `ref`; pass `invalid`, `aria-describedby`, `id`, `name`, `onBlur` from React Hook Form (`Controller` for the value).
- **`ComboboxAddRow`** is the member/role picker: optional type select, searchable subject, optional role select, Add, and a removable result list (duplicates ignored, announced via a live region).
- **`AppPageLayout`** fixes the page header (breadcrumb slot, title, description, actions slot) and fills the viewport below the top bar (`offset`, default 6 rem, same as `WizardLayout`): the page never scrolls, only the content region does. Use `scroll={false}` to host a `DataTable height="fill"` or `<WizardLayout fill>`.
- **`DataTable`** (TanStack Table v8): sticky column header, body scrolls inside the table (`height="fill"` or `maxHeight`), sorting header buttons with `aria-sort`, `onRowClick` rows focusable and activated with Enter/Space, slots for loading (8 skeleton rows), empty, error, unauthorized, and a "Load more" footer (`hasMore`/`onLoadMore`).
- **Scrolling:** `@import "@qmentisai/ui/scroll.css"` (tenant-web entry only) enables `.qm-scroll`: thin scrollbar that is invisible when idle and fades in on hover, focus inside or scroll, plus smooth scrolling (disabled under `prefers-reduced-motion`). `AppPageLayout` and `DataTable` apply it; add the class to other tenant scroll containers.

### Tenant-web `Select` is a Combobox wrapper (2026-11-13)

`apps/tenant-web/src/components/ui/select.jsx` keeps the `<option>`-children API (`value`, `onChange(e)` with `e.target.value`) but renders the shared `Combobox`. An empty option acts as the placeholder and enables Clear; selects without one have no Clear. With React Hook Form use `Controller` (pass `ref`, `onBlur`, `name`, `aria-invalid`), not `register`. Date and time inputs stay native until an accessible picker exists.

`ComboboxAddRow` (2026-11-13): Add stays disabled until a role is chosen; a duplicate (same type, value and role) or a `validateAdd` refusal shows an inline message tied to the subject field and is announced; list rows are focusable, Delete/Backspace removes and focus moves to the neighbour (or the subject field when empty); the list scrolls inside `listMaxHeight`.

### Tenant-web page frames and tables (2026-11-13)

Every tenant page renders inside `AppPageLayout` (`@qmentisai/ui`); the shell (`AppLayout`) is `h-dvh overflow-hidden`, so neither the shell nor the document scrolls (the `main` region only scrolls as a fallback for whole-page error and not-found states). The header (title, description, actions) stays put.

- **List pages** (Repositories, Pipelines, Workspaces, Audit logs): `AppPageLayout scroll={false}`, the filter bar (`shrink-0`) above a `QueryTable` (`components/common/query-table.jsx`, a `DataTable height="fill"` fed by a TanStack Query result). Loading, error (403 unauthorized, 404 not found, else Retry) and empty states use the table slots. Page-number paging stays in the table footer slot; sorting maps the URL `sort` (`field:asc|desc`) to TanStack sorting via `lib/table-sort.js`. Rows that open a detail page also activate on Enter/Space (links inside the row keep working).
- **Detail pages with tabs** (Repository, Pipeline, Members & groups, Account): `AppPageLayout scroll={false}` + `ScrollTabs` / `ScrollTabsContent` (`components/ui/scroll-tabs.jsx`). Header and tab bar stay fixed; only the active panel scrolls. A panel that hosts a filling table uses `className="flex flex-col overflow-hidden pb-0"`. Tables stacked in one panel (Executions, Configuration) use `height="auto"` with a `maxHeight` and scroll inside.
- **Forms, dashboards, planned pages**: `AppPageLayout` with the default scrolling content region. A stepper or tab bar that must stay visible is `sticky top-0` inside that region (Create workspace, Integrations catalog).
- **Wizards** (Create pipeline, Connect repository): `AppPageLayout scroll={false}` hosting `<WizardLayout fill>` without a `title` (the page header is the only header).
- Menus, tooltips and dialogs opened from table rows are portaled, so the internal scroller never clips them. Clicks that bubble from portaled content to a row do not activate the row.

### Root Console page frames and tables (2026-11-13)

The Root Console uses the same primitives as the tenant frame above: shell `h-dvh overflow-hidden`, every page in `AppPageLayout offset="7.5rem"` (1.5 rem environment strip + 3 rem top bar + 3 rem padding), list pages as `AppPageLayout scroll={false}` + `QueryTable` (`DataTable height="fill"`), the wizard as `<WizardLayout fill>`, and `scroll.css` imported by its entry so `.qm-scroll` (smooth, thin fading scrollbar, reduced-motion aware) covers `main`, the content region, the table scroller and the sidebar. Details: `ROOT_CONSOLE_DESIGN.md` §5.
