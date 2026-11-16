# QmentisAI Tenant Application — RBAC Navigation & Wireframe Spec (Google Stitch)

**App:** `apps/tenant-web`  **Status:** Draft  **Source docs:** PROJECT_CONTEXT, FRONTEND_ARCHITECTURE, AUTHORIZATION (ref), FEATURE_CATALOG, PRODUCT_REQUIREMENTS, GLOSSARY

Status labels used in this file (per README):
- **Confirmed** — stated in the project docs.
- **Recommended** — proposed here; validate before treating as a requirement.
- **Open** — needs a decision.

---

## 0. How to use this file with Google Stitch

1. Create one Stitch project: "QmentisAI Tenant App". Choose **Web**, desktop canvas **1440 × 900**.
2. Paste the **Global Design Brief** (Section 2) as the first prompt. Generate the App Shell screens (T-00a, T-00b) first.
3. Then paste one **screen prompt** at a time (Section 6). Start each with: *"Using the same QmentisAI design system and app shell as previous screens, …"* (already included in each prompt).
4. Generate role variants only where noted ("RBAC variant") — e.g. Dashboard as Admin vs Developer.
5. Export to Figma / code once the shell is stable; Stitch output is a wireframe reference, not production code.

---

## 1. Design system

> **Note:** The documentation specifies the UI stack (shadcn/ui, Tailwind CSS, shared design tokens, Lucide icons, Recharts, Sonner) and the need for reusable severity / status / SLA / quota components, but **does not define brand colors**. **Reconciled with `docs/design/DESIGN_SYSTEM.md` (2026-11-16):** the brand accent is **Electric Mint** (user-selectable from a fixed palette, mint default); indigo is withdrawn and appears nowhere in the accent role. The accent rows of the table below are updated to the design-system values; where any other value here differs from `DESIGN_SYSTEM.md` (neutrals, surfaces), the design system governs. Severity, status and lifecycle colours are kept as written. This wireframe is illustrative input for design generation, not the token source.

### 1.1 Core tokens (Recommended — shadcn/ui naming)

| Token | Light | Dark | Tailwind ref | Use |
|---|---|---|---|---|
| `--background` | `#FFFFFF` | `#020617` | white / slate-950 | Page background |
| `--foreground` | `#0F172A` | `#F8FAFC` | slate-900 / slate-50 | Primary text |
| `--muted` | `#F1F5F9` | `#1E293B` | slate-100 / slate-800 | Table headers, subtle fills |
| `--muted-foreground` | `#64748B` | `#94A3B8` | slate-500 / slate-400 | Secondary text, labels |
| `--border` | `#E2E8F0` | `#1E293B` | slate-200 / slate-800 | Card, table, input borders |
| `--card` | `#FFFFFF` | `#0F172A` | white / slate-900 | Cards |
| `--sidebar` | `#F8FAFC` | `#0F172A` | slate-50 / slate-900 | Left navigation |
| `--primary` | `#087F70` | `#40E0C0` | Electric Mint (design system) | Primary action, active nav, focus (accent is user-selectable; mint default) |
| `--primary-hover` | `#06695D` | `#6BEBD0` | Electric Mint (design system) | Hover |
| `--primary-tint` (was `--primary-soft`) | `#E6F2F1` | `#112625` | Electric Mint tint (design system) | Active nav item background, selected row |
| `--destructive` | `#DC2626` | `#EF4444` | red-600 / red-500 | Delete, revoke, reject |
| `--ring` | `#087F70` | `#40E0C0` | follows `--primary` | Keyboard focus ring (2px) |

### 1.2 Severity colors (Recommended — used by `SeverityBadge`, charts)

| Severity | Solid (chart/badge bg) | Soft badge bg | Text on soft |
|---|---|---|---|
| Critical | `#B91C1C` red-700 | `#FEE2E2` red-100 | `#991B1B` red-800 |
| High | `#EA580C` orange-600 | `#FFEDD5` orange-100 | `#9A3412` orange-800 |
| Medium | `#D97706` amber-600 | `#FEF3C7` amber-100 | `#92400E` amber-800 |
| Low | `#2563EB` blue-600 | `#DBEAFE` blue-100 | `#1E40AF` blue-800 |
| Info | `#64748B` slate-500 | `#F1F5F9` slate-100 | `#334155` slate-700 |

Always pair color with a text label or icon (accessibility — never color alone).

### 1.3 Status colors (Recommended)

| Domain | State → color |
|---|---|
| Pipeline / execution | Queued `#64748B` slate · Running `#0284C7` sky-600 (animated) · Succeeded `#16A34A` green-600 · Failed `#DC2626` red-600 · Cancelled `#71717A` zinc-500 · Partial `#D97706` amber-600 |
| Finding lifecycle | New `#4F46E5` indigo · In review `#7C3AED` violet-600 · TP confirmed `#DC2626` red · False positive `#64748B` slate · Awaiting approval `#D97706` amber · Assigned `#0284C7` sky · Fixed–pending verification `#0D9488` teal-600 · Verified fixed `#16A34A` green · Accepted risk `#CA8A04` yellow-600 · Suppressed `#94A3B8` slate-400 · Reopened/Recurred `#BE123C` rose-700 |
| Connection health | Healthy green-600 · Degraded amber-600 · Disconnected red-600 · Not configured slate-400 |
| SLA | On track green-600 · Due soon (≤ 20%) amber-600 · Breached red-600 |
| Quota | < 70% primary · 70–90% amber-600 · > 90% red-600 |

### 1.4 Typography, spacing, components

- Font: **Inter** (UI), **JetBrains Mono** (code, hashes, fingerprints, commit SHAs, logs). — Recommended
- Scale: Page title 24/32 semibold · Section 18/28 semibold · Body 14/20 · Table 13/20 · Caption 12/16.
- 8px spacing grid, card radius 8px (shadcn `--radius: 0.5rem`), 1px borders, minimal shadows.
- Components: shadcn/ui (Button, Card, Table via TanStack Table, Tabs, Dialog, Sheet, DropdownMenu, Command palette, Badge, Tooltip, Select, Form, Toast via Sonner), Lucide icons, Recharts charts.
- Density: compact data-heavy enterprise security product; tables are the primary surface.
- Every screen needs: loading (skeleton), empty, error (with correlation ID), and no-permission states.

---

## 2. Global Design Brief (paste first into Stitch)

```
Design a desktop web application (1440px wide) called "QmentisAI" — an AI-native security engineering workflow platform for enterprise security teams and developers. It connects source repositories, security scan pipelines (SCA, SBOM, SAST, Secret Scanning, manual DAST), findings, human security review, lead approvals and developer remediation.

Style: clean, professional, data-dense enterprise SaaS, built with shadcn/ui and Tailwind CSS conventions. Light theme. White page background, slate-50 (#F8FAFC) left sidebar, slate-200 (#E2E8F0) 1px borders, 8px corner radius, minimal shadows. Primary color is the design-system accent `--primary` (Electric Mint, `#087F70` light / `#40E0C0` dark; user-selectable) for the primary button, active navigation and focus only; `--primary-tint` (`#E6F2F1`) for the active nav item background. Text slate-900 (#0F172A), secondary text slate-500 (#64748B). Font Inter; monospace JetBrains Mono for commit SHAs, fingerprints and logs. Lucide-style line icons.

Severity colors: Critical #B91C1C, High #EA580C, Medium #D97706, Low #2563EB, Info #64748B — shown as soft pill badges with text labels. Success #16A34A, Running #0284C7, Failed #DC2626.

App shell: a fixed top bar (64px) with the QmentisAI logo on the left, a global search / command palette (⌘K) in the center, and on the right a notifications bell and an account avatar menu (the account menu exists ONLY in the top bar). A fixed left sidebar (256px) with grouped navigation sections and small uppercase group labels. The sidebar has no profile area. Main content area has a page header (title, breadcrumb, primary action button on the right) above the content.
```

---

## 3. App shell and the two layouts (Confirmed)

The shell picks a layout from the URL (`useNavContext`).

### 3.1 Organization layout — outside a workspace
- Sidebar header: Tenant/organization name.
- Groups: **Main**, **Administration**.

### 3.2 Workspace layout — inside `/workspaces/:workspaceId/...`
- Sidebar header: "← All workspaces" link + **Workspace switcher** (dropdown of accessible workspaces if > 1, static label if exactly 1).
- Groups: **Workspace**, **Security**, **Workspace Administration**.
- Repository details and `/repositories/connect?workspace=:id` use the layout of the repository's workspace.

### 3.3 Top bar (both layouts)
Logo · Command palette search · Notifications bell (badge count) · Account menu (Profile, Preferences, Theme, Sign out). No account area in the sidebar.

---

## 4. RBAC-driven navigation model

### 4.1 Rules (Confirmed)
1. Nav items are defined once in `@qmentisai/shared` (`ORG_NAV_GROUPS`, `WORKSPACE_NAV_GROUPS`). The app adds only labels, routes and icons (`components/layout/nav.js`).
2. Visibility = central authorization engine evaluates the item's **permission** in the right **scope** (tenant scope for Org layout; active workspace for Workspace layout). **No code checks role names.**
3. Item is shown only if: `implemented === true` **AND** permission granted **AND** route exists.
4. A group with zero visible items is hidden entirely (Recommended).
5. Frontend checks are usability aids only — backend enforces every request (403 not permitted, 404 not accessible).
6. Group membership alone grants nothing; roles assigned to groups do.
7. Effective permissions = built-in roles + custom roles, assigned at tenant scope or per workspace, to users or groups.

### 4.2 Organization navigation (Confirmed)

| Group | Item | Route | Permission (tenant scope) | Icon (Recommended) |
|---|---|---|---|---|
| Main | Organization Overview | `/overview` | `dashboard.view` | LayoutDashboard |
| Main | Workspaces | `/workspaces`, `/workspaces/new` | `workspace.view` (in any workspace) | FolderKanban |
| Administration | Users & Groups | `/users`, `/groups` | `tenant_user.view` | Users |
| Administration | Integrations | `/integrations` | `integration.view` | Plug |
| Administration | Roles & Permissions | `/roles` | `tenant_user.view` | ShieldCheck |
| Administration | Organization Settings | `/settings` | `tenant_settings.view` | Settings |
| Administration | Audit Logs | `/audit-logs` | `audit_log.view_all` | ScrollText |

### 4.3 Workspace navigation (Confirmed for implemented items)

| Group | Item | Route | Permission (in workspace) | Implemented |
|---|---|---|---|---|
| Workspace | Dashboard | `/workspaces/:id/dashboard` | `workspace.view` | Yes |
| Workspace | Repositories | `/workspaces/:id/repositories` | `repository.view` | Yes |
| Workspace | Pipelines | `/workspaces/:id/pipelines` | `pipeline.view` | Yes |
| Workspace | Executions | `/workspaces/:id/executions` | `execution.view` *(exists in the catalog; amended 2026-11-12)* | **No** |
| Security | Findings | `/workspaces/:id/findings` | `finding.view` *(Rec.)* | **No** |
| Security | Security Reviews | `/workspaces/:id/reviews` | `finding.review` *(Rec.)* | **No** |
| Security | Approvals | `/workspaces/:id/approvals` | `finding.approve` *(Rec.)* | **No** |
| Security | Remediation | `/workspaces/:id/remediation` | `remediation.view` *(Rec.)* | **No** |
| Security | Policies | `/workspaces/:id/policies` | `policy.view` | Yes |
| Security | Reports | `/workspaces/:id/reports` | `report.view` *(Rec.)* | **No** |
| Workspace Admin | Members & Groups | `/workspaces/:id/members` | `workspace.view` | Yes |
| Workspace Admin | Roles & Permissions | `/workspaces/:id/roles` | `workspace.view_roles` | Yes |
| Workspace Admin | Integrations | `/workspaces/:id/integrations` | `integration.view` *(Rec.)* | **No** |
| Workspace Admin | Activity | `/workspaces/:id/activity` | `workspace.view_activity` | Yes |
| Workspace Admin | Settings | `/workspaces/:id/settings` | `workspace.update` | Yes |

Items with `implemented: false` stay hidden in the product (no placeholder pages — Confirmed). **They are still wireframed here** so design is ready when modules start (Recommended).

### 4.4 Default role → navigation visibility (Recommended defaults — validate against AUTHORIZATION.md)

Legend: ● visible · ◐ visible, read-only (actions hidden/disabled) · — hidden

| Nav item | Admin | Manager | Lead | Security Analyst | Dev Lead | Developer | Guest/Viewer |
|---|---|---|---|---|---|---|---|
| Org Overview | ● | ● | ● | ● | ● | ● | ◐ |
| Workspaces | ● | ● | ● | ● | ● | ● | ◐ |
| **Administration group** | ● | — | — | — | — | — | — |
| WS Dashboard | ● | ● | ● | ● | ● | ● | ◐ |
| Repositories | ● | ● | ◐ | ◐ | ● | ◐ | ◐ |
| Pipelines | ● | ● | ● | ◐ | ● | ◐ | ◐ |
| Executions | ● | ● | ● | ● | ● | ● | ◐ |
| Findings | ● | ● | ● | ● | ● | ◐ (assigned) | ◐ |
| Security Reviews | ● | ◐ | ● | ● | — | — | — |
| Approvals | ● | ◐ | ● | — | — | — | — |
| Remediation | ● | ● | ● | ◐ | ● | ● | ◐ |
| Policies | ● | ◐ | ● | ◐ | ◐ | — | — |
| Reports | ● | ● | ● | ● | ● | — | ◐ |
| Members & Groups | ● | ● | ◐ | ◐ | ◐ | ◐ | ◐ |
| WS Roles | ● | ◐ | — | — | — | — | — |
| WS Integrations | ● | ● | ◐ | — | ◐ | — | — |
| Activity | ● | ● | ● | ◐ | ◐ | — | — |
| WS Settings | ● | ◐* | — | — | — | — | — |

\* Confirmed: tenant Administration is hidden from Manager and workspace Admin. Workspace Settings requires `workspace.update`; whether Manager holds it is **Open**.

### 4.5 Action-level RBAC patterns (Recommended)
- **Hide** an action when the user can never perform it in this scope (e.g. "Delete workspace" for Developer).
- **Disable + tooltip** ("You need permission to run pipelines in this workspace"; the key is `execution.run`, never shown in a 403 body) when the user can see the object but the action depends on a missing permission and they may reasonably request it.
- Segregation of duties: the Security Analyst who records a TP/FP decision cannot approve the same decision; show Approve disabled with tooltip "You reviewed this finding."
- Never show counts or names of resources the user cannot access.

### 4.6 Navigation behavior (Confirmed)
- Switching workspace keeps the current section + dashboard filters if permitted in the target workspace; otherwise opens target Dashboard.
- Workspace pages remount per workspace; cache keys include workspace id.
- Legacy redirects: `/workspaces/:id` → `/dashboard`; `/workspaces/:id/edit` → `/settings`; `/repositories` → last/first accessible workspace's Repositories.

---

## 5. Screen inventory — Tenant Application

**Total: 46 screens** (12 implemented now · 6 placeholder · 28 recommended/planned). Dialog/drawer screens are counted because Stitch generates them separately.

| ID | Screen | Route | Permission | Status |
|---|---|---|---|---|
| T-00a | App shell — Organization layout | — | — | Confirmed |
| T-00b | App shell — Workspace layout | — | — | Confirmed |
| T-01 | Sign in | `/login` | public | Confirmed (mock auth) |
| T-02 | MFA verification | `/login/mfa` | public | Recommended |
| T-03 | Account profile & preferences | `/account` | authenticated | Recommended |
| T-04 | Notifications center (drawer) | top bar | authenticated | Recommended |
| T-05 | 403 / 404 / error states | — | — | Confirmed (behavior) |
| T-06 | Organization Overview | `/overview` | `dashboard.view` | Confirmed |
| T-07 | Workspaces list | `/workspaces` | `workspace.view` | Confirmed |
| T-08 | Create workspace | `/workspaces/new` | `workspace.create` (Rec.) | Confirmed |
| T-09 | Users list | `/users` | `tenant_user.view` | Placeholder |
| T-10 | User detail & role assignments | `/users/:id` | `tenant_user.view` | Recommended |
| T-11 | Invite user (dialog) | `/users` | `tenant_user.manage` (Rec.) | Recommended |
| T-12 | Groups list & group detail | `/groups` | `tenant_user.view` | Placeholder |
| T-13 | Integrations catalog | `/integrations` | `integration.view` | Placeholder |
| T-14 | Integration connect / detail | `/integrations/:provider` | `integration.manage` (Rec.) | Recommended |
| T-15 | Roles & Permissions list | `/roles` | `tenant_user.view` | Placeholder |
| T-16 | Custom role editor (permission matrix) | `/roles/:id` | `role.manage` (Rec.) | Recommended |
| T-17 | Organization Settings (tabbed) | `/settings` | `tenant_settings.view` | Placeholder |
| T-18 | Usage & consumption (settings tab) | `/settings/usage` | `tenant_settings.view` | Recommended |
| T-19 | Audit Logs | `/audit-logs` | `audit_log.view_all` | Placeholder |
| T-20 | Workspace Dashboard — Chart view | `/workspaces/:id/dashboard` | `workspace.view` | Confirmed |
| T-21 | Workspace Dashboard — Table view | `?view=table` | `workspace.view` | Confirmed |
| T-22 | Repositories list | `/workspaces/:id/repositories` | `repository.view` | Confirmed |
| T-23 | Connect repository | `/repositories/connect?workspace=:id` | `repository.create` (Rec.) | Confirmed |
| T-24 | Repository detail | `/repositories/:repositoryId` | `repository.view` | Confirmed |
| T-25 | Pipelines list | `/workspaces/:id/pipelines` | `pipeline.view` | Confirmed |
| T-26 | Create / edit pipeline (wizard) | `/workspaces/:workspaceId/pipelines/new?repository=:id`, `/workspaces/:workspaceId/pipelines/:pipelineId/edit` (amended 2026-11-12, owner C4; `/pipelines/...` aliases redirect) | `pipeline.manage` | Confirmed |
| T-27 | Pipeline detail | `/workspaces/:workspaceId/pipelines/:pipelineId` (amended 2026-11-12, owner C4; `/pipelines/:id` alias redirects) | `pipeline.view` | Confirmed |
| T-28 | Executions list | `/workspaces/:id/executions` | `execution.view` | Planned |
| T-29 | Execution detail (live) | `/executions/:id` | `execution.view` | Planned |
| T-30 | Manual scan request (DAST / Asset Discovery) | dialog | `scan.run_manual` (Rec.) | Planned |
| T-31 | Findings list | `/workspaces/:id/findings` | `finding.view` | Planned |
| T-32 | Finding detail | `/findings/:id` | `finding.view` | Planned |
| T-33 | Accepted risk / suppression request (dialog) | dialog | `finding.accept_risk` (Rec.) | Planned |
| T-34 | Security Reviews queue | `/workspaces/:id/reviews` | `finding.review` | Planned |
| T-35 | Approvals queue | `/workspaces/:id/approvals` | `finding.approve` | Planned |
| T-36 | Remediation board | `/workspaces/:id/remediation` | `remediation.view` | Planned |
| T-37 | Policies list | `/workspaces/:id/policies` | `policy.view` | Confirmed |
| T-38 | Policy editor | `/policies/:id` | `policy.manage` (Rec.) | Recommended |
| T-39 | Reports | `/workspaces/:id/reports` | `report.view` | Planned |
| T-40 | Workspace Members & Groups | `/workspaces/:id/members` | `workspace.view` | Confirmed |
| T-41 | Workspace Roles & Permissions | `/workspaces/:id/roles` | `workspace.view_roles` | Confirmed |
| T-42 | Workspace Integrations | `/workspaces/:id/integrations` | `integration.view` | Planned |
| T-43 | Workspace Activity | `/workspaces/:id/activity` | `workspace.view_activity` | Confirmed |
| T-44 | Workspace Settings | `/workspaces/:id/settings` | `workspace.update` | Confirmed |
| T-45 | Global command palette (⌘K) | overlay | authenticated | Recommended |

---

## 6. Screen specifications and Stitch prompts

Each prompt is self-contained. Paste after the Global Design Brief.

### T-00a — App shell, Organization layout
- Sidebar: org name header; **Main** (Organization Overview, Workspaces); **Administration** (Users & Groups, Integrations, Roles & Permissions, Organization Settings, Audit Logs).
- Variants: Admin (all groups) and Developer (Main only).

```
Using the QmentisAI design system, create the application shell in "Organization layout". Top bar 64px: QmentisAI logo left, centered search input "Search or jump to… ⌘K", right side notification bell with red count badge "3" and a circular avatar "QS" with a dropdown chevron. Left sidebar 256px, background #F8FAFC, header shows organization name "Acme Corp" with a small building icon. Group label "MAIN": Organization Overview (active, `--primary-tint` background, accent text and left 2px accent bar), Workspaces. Group label "ADMINISTRATION": Users & Groups, Integrations, Roles & Permissions, Organization Settings, Audit Logs. No profile area in the sidebar. Main area shows an empty page header "Organization Overview" with breadcrumb "Acme Corp / Overview".
```
RBAC variant prompt:
```
Create the same Organization layout shell for a Developer user: the sidebar shows only the "MAIN" group (Organization Overview, Workspaces). The ADMINISTRATION group is completely absent, with no empty space or locked items.
```

### T-00b — App shell, Workspace layout
```
Using the QmentisAI design system, create the application shell in "Workspace layout". Same top bar. Left sidebar header: a small text link "← All workspaces", below it a workspace switcher button showing a colored square avatar "PA" and name "Payments API" with an up/down chevron; show the open dropdown listing 4 workspaces (Payments API ✓, Mobile App, Data Platform, Internal Tools) with a search field. Navigation groups: "WORKSPACE": Dashboard (active), Repositories, Pipelines, Executions. "SECURITY": Findings (badge "128"), Security Reviews (badge "12"), Approvals (badge "4"), Remediation, Policies, Reports. "WORKSPACE ADMINISTRATION": Members & Groups, Roles & Permissions, Integrations, Activity, Settings. No profile area in the sidebar.
```
RBAC variant: *Developer in workspace* → shows Dashboard, Repositories, Pipelines, Executions, Findings, Remediation, Members & Groups only.

### T-01 — Sign in
- Email + password, "Continue with SSO" button, tenant/org hint, error banner. Mock auth now (Confirmed); SSO is Recommended.
```
Create the QmentisAI sign-in page. Split layout: left 50% panel in slate-950 (#020617) with the QmentisAI logo, headline "Security engineering, one workflow." and three small feature lines with icons (Automated SCA, SBOM, SAST & Secrets · Human review and approvals · Developer remediation tracking). Right 50% white with a centered 400px card: title "Sign in to your organization", fields Work email and Password, link "Forgot password?", primary accent button "Sign in", divider "or", outline button "Continue with SSO". Show an inline error alert variant at the top of the card: "Invalid email or password."
```

### T-02 — MFA verification
```
Create an MFA verification screen for QmentisAI using the same split layout as sign-in. Card title "Two-factor verification", subtext "Enter the 6-digit code from your authenticator app", six separate digit input boxes, checkbox "Trust this device for 30 days", primary button "Verify", link "Use a recovery code instead".
```

### T-03 — Account profile & preferences
```
Create an Account page in the Organization layout shell. Page title "Account". Tabs: Profile, Security, Notifications, Preferences. Profile tab: avatar upload, name, email (read-only), job title, time zone select. Right-side card "Your access": list of role assignments as rows — "Admin · Organization", "Lead · Payments API", "Developer · Mobile App" — read-only with an info note "Roles are managed by your organization administrator." Security tab preview not required.
```

### T-04 — Notifications center
```
Create a notifications drawer sliding from the right (400px) over the QmentisAI workspace screen. Header "Notifications" with "Mark all as read" link and filter tabs All / Mentions / Approvals. List items with icon, title, workspace label, relative time and unread dot: "Execution #482 failed — payments-service · main pipeline", "4 findings awaiting your approval — Payments API", "Critical finding assigned to you: Hardcoded AWS key", "GitHub connection degraded — Mobile App". Footer link "Notification settings".
```

### T-05 — Error / permission states
```
Create three centered empty-state variants inside the QmentisAI Workspace layout shell, side by side as separate frames: (1) 403 "You don't have permission to view this page" with lock icon, text "Ask a workspace administrator for access." and button "Back to dashboard"; (2) 404 "Not found" with text "This resource doesn't exist or you don't have access to it." (never confirm existence); (3) Error "Something went wrong" with a small mono text "Correlation ID: 7f3c-91ab-…" and copy icon, button "Retry".
```

### T-06 — Organization Overview
- KPI row (accessible workspaces, open criticals, executions 7d, SLA breaches), workspace cards linking to each dashboard. Only accessible workspaces are listed (Confirmed).
```
Create the "Organization Overview" page in the Organization layout shell. Header with title and period select "Last 30 days". KPI row of 4 cards: Workspaces 6, Open Critical findings 14 (red), Executions (7d) 312, SLA breaches 5 (red). Below, section "Your workspaces" as a 3-column grid of cards; each card: workspace name, description, role chip ("Lead"), mini severity bar (Critical/High/Medium/Low counts with severity colors), repositories count, pipelines count, last execution status pill, and link "Open dashboard →". Right sidebar card "Recent activity" with 6 compact activity rows.
```

### T-07 — Workspaces list
```
Create the "Workspaces" list page in the Organization layout. Header with primary button "New workspace" (shown only to users with create permission). Toolbar: search, filter "My role", toggle Grid/Table. Table columns: Name, Description, Your role, Repositories, Pipelines, Open findings (severity mini-badges), Last activity, row action menu. 6 rows of realistic data. Empty-state variant: illustration, "No workspaces yet", button "Create workspace".
```

### T-08 — Create workspace
```
Create a "New workspace" form page in the Organization layout. Single-column 640px form card: Name, Slug (auto-generated, editable, mono), Description textarea, Default SLA policy select, "Add initial members" multi-select with avatars and role select per member (Admin, Manager, Lead, Security Analyst, Dev Lead, Developer, Guest/Viewer). Footer: Cancel and primary "Create workspace". Show inline validation error on Slug: "Slug already in use."
```

### T-09 — Users list
```
Create the "Users & Groups" page in the Organization layout with tabs "Users" (active) and "Groups". Toolbar: search, filters Status (Active, Invited, Disabled), Role, Workspace; primary button "Invite user". Table: avatar+name+email, Status pill, Organization roles (chips), Workspaces count, MFA (✓/✗), Last sign-in, row actions (View, Disable, Resend invite). Bulk selection checkbox column with bulk action bar "Disable / Add to group".
```

### T-10 — User detail & role assignments
```
Create a "User detail" page. Header: avatar, name, email, status pill, actions "Disable user", "Reset MFA". Tabs: Overview, Role assignments, Groups, Sessions, Activity. Role assignments tab: table with columns Role, Scope (Organization or workspace name), Assigned via (Direct / Group "Security Team"), Assigned by, Date, remove action; button "Assign role" opens a side sheet with Role select, Scope select (Organization / specific workspace) and Save. Show a callout: "Group membership alone does not grant permissions; roles assigned to the group do."
```

### T-11 — Invite user dialog
```
Create a modal dialog "Invite users" over the Users page: email input accepting multiple emails as chips, "Organization role" select (optional), "Workspace access" repeater rows (Workspace select + Role select + remove), checkbox "Send invitation email", buttons Cancel / Send invites.
```

### T-12 — Groups
```
Create the Groups tab of "Users & Groups": left 360px list of groups (Security Team, Payments Devs, Platform Leads) with member counts; right detail panel for "Security Team": description, Members table (add/remove), and "Role assignments" table (Role, Scope) with an "Assign role to group" button.
```

### T-13 — Integrations catalog
```
Create an "Integrations" catalog page in the Organization layout. Category tabs: All, Source control, AI coding tools, Ticketing, Collaboration, Security tools, Cloud, Secrets. Grid of integration cards with logo placeholder, name, short description, status pill (Connected green / Degraded amber / Not connected slate) and button "Connect" or "Manage". Include GitHub (Connected), GitLab, Bitbucket, Cursor, Claude Code, Codex, Kiro, Jira, Linear, Slack, Microsoft Teams, Semgrep, SonarQube, Snyk, Trivy, OWASP ZAP, Burp, AWS, Azure, GCP, Vault. Mark AI coding tools with a small "Beta" badge.
```

### T-14 — Integration detail
```
Create an "Integration detail" page for GitHub. Header: logo, "GitHub", status pill "Healthy", buttons "Test connection" and destructive "Disconnect". Sections: Connection (installation/org name, auth method, connected by, connected on — never show tokens, only "••••• last rotated 12 days ago"), Capabilities (checklist: Webhooks ✓, PR comments ✓, Commit status ✓), Scope (which workspaces may use this connection, multi-select), Webhook health (last delivery, success rate, recent deliveries table with signature verified ✓), Events log.
```

### T-15 — Roles & Permissions list
```
Create a "Roles & Permissions" page in the Organization layout. Two sections: "Built-in roles" table (Admin, Manager, Lead, Security Analyst, Dev Lead, Developer, Guest/Viewer) with columns Name, Description, Permissions count, Assignments count, "Built-in" lock badge, action "View". "Custom roles" table with button "Create custom role" and actions View/Edit/Duplicate/Delete. Read-only variant for users without manage permission (buttons hidden).
```

### T-16 — Custom role editor
```
Create a "Custom role editor" page. Fields: Role name, Description, "Based on" select. Main area: a permission matrix grouped by domain with collapsible sections — Workspace, Repository, Pipeline, Execution, Finding, Review & Approval, Remediation, Policy, Report, Integration, Users & Roles, Settings, Audit. Each row: permission key in mono (e.g. finding.approve), human description, checkbox. Right sticky summary card: "24 permissions selected", warning callout when a role combines finding.review and finding.approve ("Segregation of duties: reviewers cannot approve their own decisions"). Footer Save / Cancel.
```

### T-17 — Organization Settings
```
Create an "Organization Settings" page with a left vertical settings nav: General, Authentication & SSO, Notifications, API & developer, Usage & consumption, Data governance. Show General: organization name, logo upload, default time zone, default SLA targets by severity (Critical/High/Medium/Low days inputs, marked "Configurable"), Save button. Disabled read-only variant for users with view-only permission with a banner "You can view but not change these settings."
```

### T-18 — Usage & consumption
```
Create the "Usage & consumption" settings tab. Plan card: plan name, billing period, renewal date (no prices). Quota meters as horizontal progress bars with color thresholds (neutral below the warning threshold, warning amber, danger red; thresholds per the design-system QuotaMeter, values open, the numbers in this example are illustrative): Scan executions 7,420 / 10,000; Repositories 48 / 50 (red); Users 62 / 100; Manual DAST scans 3 / 10. Below, a Recharts line chart "Executions per day" for 30 days and a table of usage by workspace. Info note: "Limits are set by your subscription. Contact your account team to change them."
```

### T-19 — Audit Logs
```
Create an "Audit Logs" page. Toolbar: date range, Actor, Action category (Auth, Permissions, Workspace, Pipeline, Finding decision, Integration, Export), Workspace, Result (Success/Denied), search, button "Export CSV". Dense table: Timestamp, Actor (avatar + email), Action (mono, e.g. role.assigned), Target, Workspace, IP, Result pill, Correlation ID (mono, truncated). Clicking a row opens a right sheet with full event JSON (redacted secrets shown as "[REDACTED]") and before/after diff.
```

### T-20 — Workspace Dashboard (Chart view)
- No workspace filter (Confirmed). Filters: period, severity (bar click), Refresh, Chart/Table toggle (URL `period`, `sev`, `view`).
```
Create the Workspace "Dashboard" page for workspace "Payments API" in the Workspace layout shell. Header: title "Dashboard", filters on the right: Period select "Last 30 days", segmented toggle "Chart view | Table view" (Chart active), icon button Refresh. Row 1 — posture/KPI cards: Security posture score 72/100 with trend, Open findings 128, Critical 6, Mean time to remediate 9.4 days, SLA breaches 3, Pipelines healthy 11/12. Row 2: "Findings by severity" vertical bar chart (Critical #B91C1C, High #EA580C, Medium #D97706, Low #2563EB, Info #64748B; clicking a bar filters) and "Finding lifecycle" stacked horizontal bar (New, In review, Awaiting approval, Assigned, Fixed–pending verification, Verified fixed, Accepted risk). Row 3: "Execution trend" line chart (succeeded/failed per day), "Team workload" bar chart by assignee. Row 4: "Connection health" list (GitHub Healthy, Jira Degraded) and "SLA status" donut-free progress bars (On track / Due soon / Breached).
```

### T-21 — Workspace Dashboard (Table view)
```
Create the same Workspace Dashboard in "Table view" (toggle active). Below the filters show severity toggle chips (Critical, High, Medium, Low, Info) that can be switched on/off. Content: a stack of cards each containing its own internally scrolling table (max height 320px): "Findings" (severity, title, repository, pipeline, status, age, assignee), "Pipelines" (name, repository, last run status, duration, findings), "Repositories" (name, provider, default branch, pipelines, connection health), "Workload & SLA" (assignee, open, due soon, breached), "Activity" (time, actor, action).
```

### T-22 — Repositories list
```
Create the "Repositories" page in the Workspace layout. Header button "Connect repository". Toolbar: search, Provider filter (GitHub, GitLab, Bitbucket), Health filter. Table: provider icon + repo full name (mono), default branch, Pipelines count, Last execution status pill, Open findings mini severity badges, Connection health pill, Last commit (short SHA mono + relative time), row actions. Empty state: "Connect your first repository" with provider buttons.
```

### T-23 — Connect repository
```
Create a "Connect repository" 3-step wizard (stepper at top: 1 Provider, 2 Select repositories, 3 Review). Step 2 shown: selected provider GitHub (connection "acme-org"), searchable list of repositories with checkboxes, visibility badge (Private/Public), default branch, "Already connected" disabled rows. Right summary card: target workspace "Payments API", 3 repositories selected, note "Webhooks will be registered automatically. Signatures are verified on every delivery." Footer Back / Continue.
```

### T-24 — Repository detail
```
Create a "Repository detail" page for "acme/payments-service" in the Workspace layout. Header: provider icon, repo name (mono), default branch chip, health pill, buttons "Add pipeline" and "Sync now". Tabs: Overview, Pipelines, Branches, Pull requests, Commits, Webhooks, Settings. Overview: languages bar, dependency manifests detected (package.json, pom.xml), latest SBOM card with component count and "Download SBOM", findings by severity, table of pipelines on this repository (one repository can have many pipelines, each with its own trigger and history).
```

### T-25 — Pipelines list
```
Create the "Pipelines" page in the Workspace layout. Header button "Create pipeline". Table: Pipeline name, Repository (mono), Triggers (chips: Push to main, Pull request, Schedule daily 02:00, Manual), Scans (chips: SCA, SBOM, SAST, Secrets), Last execution status + duration, Success rate (last 20), Open findings, Enabled toggle, row actions (Run now, Edit, Duplicate, Disable). Disabled "Run now" with tooltip variant for a user lacking run permission.
```

### T-26 — Create / edit pipeline wizard
```
Create a "Create pipeline" wizard with a left vertical stepper: 1 Basics, 2 Triggers, 3 Scans, 4 Execution controls, 5 Notifications, 6 Review. Show step 3 "Scans": cards for SCA, SBOM, SAST, Secret Scanning each with an enable toggle, engine select (e.g. Built-in, Semgrep, Trivy) and severity threshold select; a separate section "Manual-only scans" listing DAST and Asset Discovery with note "Run on demand from Executions; not triggered automatically." Right side card "Pipeline summary". Step 4 preview fields: Scan mode (Incremental / Full), Timeout, Concurrency, Cancellation (Immediate / Graceful), Fail pipeline on (severity select).
```

### T-27 — Pipeline detail
```
Create a "Pipeline detail" page for "payments-service · main-security". Header: status, Enabled toggle, buttons "Run now", "Edit". Tabs: Overview, Executions, Findings, Configuration, Triggers, Activity. Overview: KPI cards (Runs 30d, Success rate, Avg duration, Open findings), execution history bar strip (last 30 runs colored by status), "Findings trend" line chart. Note banner: "Findings in this pipeline have their own identity and lifecycle, independent of other pipelines."
```

### T-28 — Executions list
```
Create the "Executions" page in the Workspace layout. Toolbar: Status filter, Pipeline filter, Trigger type (Webhook, Schedule, Manual), date range; button "Run manual scan". Table: Execution # (mono), Pipeline, Repository, Trigger (icon + "PR #214 by j.doe"), Commit SHA (mono), Status pill (Running shows animated sky-600 progress), Scan tasks progress "3/4", Started, Duration, New findings, actions (View, Cancel, Retry).
```

### T-29 — Execution detail
```
Create an "Execution detail" page "Execution #482". Header: status pill "Running", pipeline, repository, commit SHA, trigger, started by, buttons "Cancel" (destructive outline) and "Retry". Horizontal stage timeline: Queued → Repository analysis → Scan decisioning → Scans → Finding normalization → Completed. Below, scan task cards (SCA ✓ 42s, SBOM ✓, SAST running 64% progress bar, Secrets queued) each expandable. Bottom tabs: Logs (dark mono log viewer with timestamps, secrets shown as [REDACTED]), Findings (new / recurring / not re-detected), Artifacts (SBOM, raw reports download), Events. Notice: "Incremental scan — absent findings are not marked fixed."
```

### T-30 — Manual scan request
```
Create a modal "Run manual scan": Scan type radio cards (DAST, Asset Discovery), Target (URL or domain list), Authentication (None / Header / Login recipe — DAST unauthenticated by default), Scan profile select, Schedule (Now / Later), confirmation checkbox "I am authorized to scan this target", quota line "Manual DAST scans used: 3 of 10 this period". Buttons Cancel / Start scan.
```

### T-31 — Findings list
```
Create the "Findings" page in the Workspace layout. Left filter panel (collapsible): Severity checkboxes with colored dots, Status (lifecycle states), Scan type (SCA, SAST, Secrets, DAST), Pipeline, Repository, Assignee, SLA (On track, Due soon, Breached), AI confidence. Main table: checkbox, Severity badge, Title, Rule/CWE (mono), Location (file:line mono), Pipeline, Status pill, SLA chip, Assignee avatar, Age, Recurrence icon. Saved views tabs at top: All open, Needs review, Assigned to me, Breached SLA. Bulk action bar: Assign, Send to review, Export.
```
RBAC variant: Developer → saved view defaults to "Assigned to me", bulk "Send to review" hidden.

### T-32 — Finding detail
```
Create a "Finding detail" page. Header: Critical severity badge, title "Hardcoded AWS access key", status pill "Awaiting approval", fingerprint (mono, copy), pipeline and repository chips. Action buttons depend on permission: "Mark TP", "Mark FP", "Approve", "Reject", "Assign", "Request accepted risk". Left main column tabs: Overview (description, location with code snippet viewer highlighting the line, secret masked), Evidence (scanner output, request/response for DAST), AI analysis (card labeled "Advisory — AI-generated, requires human decision" with confidence, reasoning, suggested fix), History (immutable timeline: detected, reviewed by, approved by, assigned, fixed, verified), Comments. Right column: Risk card, SLA countdown, Assignee, Related occurrences in this pipeline only, Ticket link (Jira).
```

### T-33 — Accepted risk / suppression dialog
```
Create a dialog "Request accepted risk" for a finding: Justification textarea (required), Compensating controls, Expiry date (required, max 180 days), Approver select (Security Lead), attach evidence. Info: "Accepted risk is time-bound and requires lead approval." Buttons Cancel / Submit for approval.
```

### T-34 — Security Reviews queue
```
Create the "Security Reviews" queue page for Security Analysts. Split view: left list of findings awaiting review (severity, title, pipeline, age, AI suggestion chip "Likely TP 87%"); right review panel for the selected finding showing evidence summary, code snippet, AI advisory card, and a decision form: radio True Positive / False Positive, rationale textarea (required), severity override select, button "Submit for approval". Keyboard hints at the bottom (J/K next/previous, T/F decide).
```

### T-35 — Approvals queue
```
Create the "Approvals" page for Security Leads. Table of pending decisions: Finding (severity + title), Decision (TP / FP / Accepted risk), Reviewed by, Rationale preview, Submitted, SLA. Selecting a row opens a right sheet with full rationale, evidence and buttons "Approve" and "Reject with comment". Show one row where Approve is disabled with tooltip "You reviewed this finding — another lead must approve."
```

### T-36 — Remediation board
```
Create the "Remediation" page with a toggle Board / Table. Board columns: Assigned, In progress, Fix submitted, Pending verification, Verified fixed, Reopened. Cards: severity badge, finding title, repository, assignee avatar, SLA chip, linked PR "#231" and Jira key. Filters: Assignee, Severity, Pipeline, SLA. Note on "Pending verification" column: "Verified by the next complete scan."
```

### T-37 — Policies list
```
Create the "Policies" page in the Workspace layout. Table: Policy name, Type (Severity gate, SLA, Suppression rule, Scan requirement), Scope (Workspace / specific pipelines), Enforcement (Enforce / Warn), Status toggle, Last updated by, actions. Header button "Create policy" (hidden for read-only users).
```

### T-38 — Policy editor
```
Create a "Policy editor" page: Name, Type select, Scope selector (all pipelines or chosen pipelines), rule builder with condition rows ("Severity is Critical AND Scan type is Secrets → Fail execution"), Enforcement mode radio (Enforce / Warn only), Effective date, change note. Right panel "Impact preview: 4 pipelines affected, 12 current findings would match". Save / Cancel.
```

### T-39 — Reports
```
Create the "Reports" page: template cards (Executive security summary, Findings by pipeline, SLA compliance, SBOM inventory, Remediation performance, Audit evidence pack) each with "Generate". Below, "Generated reports" table: name, scope, period, format (PDF/CSV/JSON), generated by, status, download (signed link, expires in 24h). Schedule report button.
```

### T-40 — Workspace Members & Groups
```
Create the workspace "Members & Groups" page with tabs Members and Groups. Members table: user, workspace roles (chips), access source (Direct / via group "Security Team" / inherited from organization role), added on, actions. Button "Add members" (only with manage permission). Read-only variant: no buttons, actions column hidden.
```

### T-41 — Workspace Roles & Permissions
```
Create workspace "Roles & Permissions": table of roles available in this workspace (built-in and custom) with member counts; selecting a role shows a read-only grouped permission list with checkmarks, and an "Assignments in this workspace" table (users and groups). Note: "Custom roles are defined at organization level."
```

### T-42 — Workspace Integrations
```
Create the workspace "Integrations" page: list of organization integrations enabled for this workspace (GitHub, Jira, Slack) with status pill, routing settings (e.g. Jira project key per pipeline, Slack channel for Critical findings), and "Enable for this workspace" toggles. Integrations not connected at organization level show "Connect at organization level" link (only for admins).
```

### T-43 — Workspace Activity
```
Create the workspace "Activity" page: vertical timeline grouped by day; each item: icon by category, actor, action sentence ("Priya approved FP decision for Finding #2231"), target link, time. Filters: actor, category, date range.
```

### T-44 — Workspace Settings
```
Create workspace "Settings" with left sub-nav: General, SLA, Notifications, Danger zone. General: name, slug, description. SLA: per-severity days. Danger zone card with red border: "Archive workspace" and "Delete workspace" buttons, each requiring typing the workspace name to confirm.
```

### T-45 — Command palette
```
Create a ⌘K command palette overlay (640px) on top of the workspace dashboard: search input, grouped results "Workspaces", "Repositories", "Findings", "Actions" (Run pipeline…, Invite user…). Only items the user can access are shown. Keyboard hint footer.
```

---

## 7. Reusable product components (Confirmed need; designs Recommended)

| Component | Variants |
|---|---|
| `SeverityBadge` | Critical/High/Medium/Low/Info × soft/solid × sm/md |
| `FindingStatusPill` | all lifecycle states (§1.3) |
| `PipelineStatusPill` | Queued/Running/Succeeded/Failed/Cancelled/Partial |
| `ScanProgress` | per-task progress bar + stage timeline |
| `SlaChip` | On track / Due soon / Breached with countdown |
| `QuotaMeter` | thresholds 70/90% |
| `ConnectionHealth` | Healthy/Degraded/Disconnected/Not configured |
| `PermissionGate` | hide / disable-with-tooltip wrapper |
| `WorkspaceSwitcher` | single (static label) / multiple (dropdown) |
| `AiAdvisoryCard` | always labeled advisory, confidence, never an action |
| `EmptyState`, `ErrorState` (with correlation ID), `NoPermissionState` | |

Stitch prompt for the component sheet:
```
Create a QmentisAI component sheet on one canvas: SeverityBadge in Critical #B91C1C, High #EA580C, Medium #D97706, Low #2563EB, Info #64748B (soft and solid); finding status pills for New, In review, Awaiting approval, TP confirmed, False positive, Assigned, Fixed–pending verification, Verified fixed, Accepted risk, Suppressed, Reopened; pipeline status pills Queued, Running (animated), Succeeded, Failed, Cancelled, Partial; SLA chips On track / Due soon / Breached; quota meters at 45%, 82%, 96%; connection health indicators; a disabled button with permission tooltip; an "AI advisory" card; empty, error and no-permission states.
```

---

## 8. Open items

- Logo (the brand accent is decided: Electric Mint default with a user-selectable palette, see `DESIGN_SYSTEM.md`; indigo is withdrawn).
- Final permission keys for planned modules (`execution.view`, `finding.review`, `finding.approve`, `remediation.view`, `report.view`, etc.).
- Default role → permission mapping (validate §4.4 against AUTHORIZATION.md).
- Whether Manager holds `workspace.update`.
- SSO/MFA timing (mock auth today).
- Dark mode in v1 or later.
