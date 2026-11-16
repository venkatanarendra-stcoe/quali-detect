# Root Console Design

**Status:** Direction documented — no Stitch screens generated yet (deferred until the Tenant Application direction is complete).
**App:** `apps/root-console` (foundation implemented 2026-11-11: shell, environment strip, login + mandatory MFA (mock), navigation, support-access banner component; all modules below are placeholders). `docs/ROOT_CONSOLE_WIREFRAME_SPEC.md` does not exist in this repository, so this document and `DESIGN_SYSTEM.md` were the source. Stitch project: `projects/7652438332940652451` ("QmentisAI Root Console"), currently empty.
**References:** `DESIGN_SYSTEM.md`, `UX_GUIDELINES.md`, `STITCH_WORKFLOW.md`, `TENANT_APPLICATION_DESIGN.md`.

The Root Console uses the same tokens, components and shell proportions as the Tenant Application, except for the Root theme below (violet accent, always-dark sidebar; decision recorded in `DESIGN_SYSTEM.md` §7). It must not share business navigation or permission models with it (FRONTEND_ARCHITECTURE.md). Platform authorization is separate from tenant roles (ADR-003).

---

## 1. Context cues (the only intended differences)

| Cue | Spec |
|---|---|
| Environment tag | The environment strip at the very top (kept; safety feature). The old "PLATFORM" top-bar chip is gone with the top bar (2026-11-16, owner decision, Confirmed); the sidebar logo reads "QmentisAI Platform" |
| No workspace switcher | Tenant context appears only inside the tenant drill-in banner |
| Tenant drill-in banner | When viewing a tenant, a bar at the top of the content area names the tenant and the access reason; cross-tenant support access is scoped, time-limited and audited |
| Sidebar header | "QmentisAI Platform" wordmark line |
| Sidebar chrome (2026-11-16, owner decision, Confirmed) | Below the header: search / command palette (⌘K) and Notifications; at the bottom: system-status indicator ("API reachable" / "API unreachable", text + dot) and the account area (avatar + name + role; menu: Account, Settings > Appearance (theme only, **no accent picker**) / Preferences, Sign out). Violet / dark identity unchanged |
| Destructive actions | Typed confirmation (tenant name) for suspend, deactivate and entitlement removal |

Typography, neutrals, status chips and severity rules are identical to the Tenant Application. The accent is **violet** instead of mint (same usage rules: primary action, active navigation, focus, links) and the sidebar is dark in both themes (`packages/ui/src/root-theme.css`).

| Added cue | Spec |
|---|---|
| Environment strip | 24 px strip across the top of every screen, including sign-in, naming the environment (`VITE_ENVIRONMENT`: Development neutral, Staging warning, Production danger; unknown values are treated as Production). Text, not color alone |
| Sign-in | Platform sign-in is two steps: password, then a **mandatory** verification code. The server withholds all platform data until MFA is complete (see `docs/AUTHORIZATION.md` §16); the mock verifier uses `MOCK_PLATFORM_MFA_CODE` |
| Support-access banner | `SupportAccessBanner` (active, expiring in the last 10 minutes, expired as an alert). Presentational only: it is rendered at the top of the content area once support-access grants exist; the server enforces grants |

## 2. Navigation

- **Platform:** Platform Dashboard, System Monitoring
- **Customers:** Tenant Management, Subscription Management, License Management, Feature Entitlements, Usage & Quotas
- **Platform administration:** Platform Users, Integration Catalog, Global Configuration
- **Operations:** Support & Diagnostics, Platform Audit Logs

## 3. Screen specifications (indicative; platform permissions TBD)

### 3.1 Platform Dashboard
Users: Platform Super Admin, platform support. Metrics: tenants by status, usage versus quota, queue and job health, error rate; recent platform audit events. Primary: drill into a tenant. Secondary: time range. No invented revenue metrics (billing is an open decision).

### 3.2 Tenant Management
Table: Tenant, Status (Active, Trial, Suspended, Deactivated), Plan, Users, Workspaces, Usage, Created. Primary: Create tenant. Secondary: suspend, reactivate, deactivate (typed confirmation), open tenant. Filters: status, plan. Support diagnostics access requires a stated reason and is audited.

### 3.3 Subscription and License Management
Shows: plan, entitlements, quotas, license grants, history. Primary: change plan or entitlement. Secondary: adjust quota, view history. **Plan names, prices and quota values are open decisions: designs use placeholders such as "Plan A" and never present them as final.**

### 3.4 Remaining modules
Feature Entitlements, Usage & Quotas (quota meters, soft/hard policy is open), Platform Users, Integration Catalog, System Monitoring (jobs, queues, errors), Platform Audit Logs, Support & Diagnostics, Global Configuration and feature flags. Specs will be added when each is designed.

## 4. Stitch screen registry (summary)

Authoritative records are in `STITCH_SCREEN_REGISTRY.md`; rules are in `STITCH_WORKFLOW.md` §6. No Root Console screens exist; generation is deferred.

| # | Module | Current screen ID | Status |
|---|---|---|---|
| 1 | Platform Dashboard | — | Planned (deferred) |
| 2 | Tenant Management | — | Planned (deferred) |
| 3 | Subscription and License Management | — | Planned (deferred) |

Generation uses the prompt template in `STITCH_WORKFLOW.md` §5, adapted with the context cues above, and the same automatic QA workflow.

## 5. Page frames and tables (2026-11-13)

The Root Console adopts the tenant-web page frame (see `UX_GUIDELINES.md` §14 "Tenant-web page frames and tables"); the Root look is unchanged (violet accent, always-dark sidebar, PLATFORM tag, environment strip). No accent picker, no `ThemeProvider`, no `data-accent`.

- **Shell:** `AppLayout` is `h-dvh overflow-hidden` (environment strip 1.5 rem, no top bar, `main` padding 1.5 rem; below 768 px a 3rem menu strip); neither the shell nor the document scrolls. Every platform page renders in `AppPageLayout offset="4.5rem"` (the same `@qmentisai/ui` component the tenant app uses; 4.5 rem is the 1.5 rem strip plus the 3 rem page padding). `main` scrolls only as a fallback for whole-page states without a header (403 route guard, 404, whole-page error).
- **Lists** (Tenant management; Platform audit logs use the audit terminal, next bullet): `AppPageLayout scroll={false}`, `shrink-0` filter bar, then `QueryTable` (`components/common/query-table.jsx`, a `DataTable height="fill"` over a TanStack Query result; sticky column header, internal scroll). Loading, error (403, 404, retry) and empty states use the table slots; both lists use numbered pages (2026-11-16, owner decision, replacing "Load more"): the shared `Pagination` of `@qmentisai/ui` in the footer slot (first, previous, page numbers with ellipses, next, last, "Rows per page" 25/50/100, "Page X of Y · N tenants"; the total only there), `page` and `limit` in the URL, `hooks/use-page-list.js` (`useListParams`, `usePageList`), any filter, sort or size change returns to page 1 and an out-of-range page is clamped to the last page. Filters, search, sort and "Clear filters" are unchanged. Sorting maps the URL `sort` to TanStack sorting (`lib/table-sort.js`); sortable columns need an `accessorKey`. Tenant rows open the tenant on click, Enter and Space (the name link keeps working).
- **Platform audit logs: audit terminal as built (2026-11-13, owner decision, item 6 extended to the Root Console):** R-28 renders `AuditTerminal` from `@qmentisai/ui` (the exception in `DESIGN_SYSTEM.md`; `terminal.css` is imported by the Root Console `index.css`). Always-dark mono panel in both themes with the neutral terminal tokens (no violet in terminal text; the violet accent, PLATFORM tag, env strip and dark sidebar elsewhere are unchanged). Prompt `platform@qmentisai-root:~$` (literal; the platform session exposes no better label) followed by the muted `tail -f audit.log`. Columns: timestamp (sortable, local `YYYY-MM-DD HH:mm:ss`), actor (name, e-mail), action (sortable), target (type, id, and `tenant <id>` when the entry is tenant-scoped), result (icon plus label). All filters stay in the URL (action, actor, tenantId, result, from, to, sort); paging is numbered (2026-11-16, owner decision, replacing the `-- more --` footer): the shared `Pagination` under the dark panel in the normal app theme, `page` and `limit` in the URL; loading, empty (no entries or no matches with `-- clear filters --`), error (`-- retry --`, correlation reference) and 403 "Permission denied" are `TerminalMessage` slots. Rows are a roving-tabindex set (ArrowUp/Down, Home/End, Enter/Space; click after 220 ms unless selecting text). A row opens the detail side sheet (`components/ui/sheet.jsx`, Radix dialog, normal Root Console theme, focus trap, Escape and overlay close, focus returns to the row) with action, time, result, actor (name, e-mail, id), resource, tenant, correlation ID, IP address and the changes/metadata JSON (the platform DTO has `changes: null`). Export is not built (Planned).
- **Detail, dashboard, planned modules, dev gallery:** `AppPageLayout` with the scrolling content region (the header stays put). Tenant detail has no tabs today (cards only); no tabs were added. Provision tenant: `AppPageLayout scroll={false}` hosting `<WizardLayout fill>`.
- **Scrolling:** `scroll.css` is imported by the Root Console entry, so `.qm-scroll` (smooth scrolling, thin scrollbar that fades in on hover, focus or scroll; disabled under `prefers-reduced-motion`) applies to `main`, the page content region, the table scroller and the sidebar (`qm-scroll-dark` picks a thumb colour for the dark sidebar). Wizard regions get the same look through `[data-wizard]` rules in `index.css`.
- Menus, tooltips and dialogs are portaled (Radix), so the internal scrollers never clip them. The tenant detail "Usage" counts (users, workspaces, groups) and the dashboard permission count are KPI/metadata values, not list totals, and stay.
