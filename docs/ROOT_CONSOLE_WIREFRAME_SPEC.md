# QmentisAI Root Console — RBAC Navigation & Wireframe Spec (Google Stitch)

**App:** `apps/root-console`  **Status:** Draft  **Source docs:** PROJECT_CONTEXT, OVERALL_ARCHITECTURE, TENANT_ISOLATION, FEATURE_CATALOG, DATABASE_DESIGN (platform entities), API_STANDARDS (platform routes)

Status labels: **Confirmed** (in docs) · **Recommended** (proposed here) · **Open** (needs decision).

---

## 0. How to use this file with Google Stitch

1. Create a **separate** Stitch project: "QmentisAI Root Console" (Web, 1440 × 900). Do not reuse the Tenant project — the Root Console must look visibly different so operators never confuse platform and tenant contexts.
2. Paste the **Global Design Brief** (Section 2) first, then the shell (R-00), then one screen prompt at a time.
3. Generate RBAC variants where noted.

---

## 1. Design system

> **Note:** The docs define the stack (shadcn/ui, Tailwind CSS, shared design tokens, Lucide, Recharts, Sonner) and require the Root Console to be a separate app sharing tokens but **not** navigation/permission models. **No colors are defined in the docs.** The palette below is **Recommended**, using Tailwind defaults and the same neutral tokens as the Tenant app, with a **distinct violet accent and a dark sidebar** to signal platform-level (privileged) context.

### 1.1 Core tokens (Recommended)

| Token | Value | Tailwind ref | Use |
|---|---|---|---|
| `--background` | `#FFFFFF` | white | Page background |
| `--foreground` | `#0F172A` | slate-900 | Text |
| `--muted` | `#F1F5F9` | slate-100 | Table header, fills |
| `--muted-foreground` | `#64748B` | slate-500 | Secondary text |
| `--border` | `#E2E8F0` | slate-200 | Borders |
| `--sidebar` | `#0F172A` | slate-900 | **Dark** sidebar (differs from tenant) |
| `--sidebar-foreground` | `#CBD5E1` | slate-300 | Sidebar text |
| `--sidebar-active` | `#1E293B` | slate-800 | Active item bg |
| `--primary` | `#7C3AED` | violet-600 | Primary buttons, active indicator, links |
| `--primary-hover` | `#6D28D9` | violet-700 | Hover |
| `--primary-soft` | `#F5F3FF` | violet-50 | Selected rows, soft badges |
| `--platform-banner` | `#020617` | slate-950 | Top "PLATFORM CONSOLE" environment strip |
| `--destructive` | `#DC2626` | red-600 | Suspend, deactivate, revoke |
| `--warning` | `#D97706` | amber-600 | Support-access banner, quota warnings |
| `--ring` | `#8B5CF6` | violet-500 | Focus ring |

### 1.2 Status colors (Recommended)

| Domain | States |
|---|---|
| Tenant lifecycle | Provisioning `#0284C7` sky-600 · Trial `#7C3AED` violet-600 · Active `#16A34A` green-600 · Suspended `#D97706` amber-600 · Deactivated `#DC2626` red-600 · Pending deletion `#71717A` zinc-500 |
| Subscription | Active green · Past due amber · Cancelled red · Expired zinc |
| System health | Operational green-600 · Degraded amber-600 · Outage red-600 · Maintenance sky-600 |
| Queues | Normal green · Backlog amber (depth > threshold) · DLQ non-empty red |
| Quota usage | < 70% violet · 70–90% amber · > 90% red |
| Feature flag | On green · Off slate-400 · Partial rollout sky-600 |

### 1.3 Typography & components
Same as Tenant app: Inter / JetBrains Mono, 8px grid, 8px radius, shadcn/ui + TanStack Table + Recharts + Sonner. Data-dense admin style.

---

## 2. Global Design Brief (paste first into Stitch)

```
Design a desktop web application (1440px wide) called "QmentisAI Root Console" — the platform administration console used by the QmentisAI operator team to provision and manage customer tenants, plans, subscriptions, licenses, entitlements, quotas, platform users, the global integration catalog, feature flags, system health and audit. It is NOT used by customers.

Style: professional, data-dense enterprise admin console built with shadcn/ui and Tailwind CSS conventions. A thin 32px environment strip at the very top in #020617 with small uppercase text "PLATFORM CONSOLE · PRODUCTION" and a violet dot. Below it a white 56px top bar with "QmentisAI Root" logo, global search "Search tenants, users, plans… ⌘K", a system-status indicator ("All systems operational" green dot), notifications bell and avatar menu. Left sidebar 256px with DARK background slate-900 (#0F172A), slate-300 text, active item slate-800 background with a 2px violet-600 (#7C3AED) left bar, small uppercase group labels in slate-500. Content area white with slate-200 (#E2E8F0) borders, 8px radius, minimal shadows. Primary color violet-600 (#7C3AED) for primary buttons and links. Destructive red-600 (#DC2626). Font Inter, mono JetBrains Mono for IDs. Lucide-style icons.

Tenant lifecycle pills: Provisioning sky-600, Trial violet-600, Active green-600, Suspended amber-600, Deactivated red-600.
```

---

## 3. App shell (Recommended)

- Environment strip (always visible; shows environment name — prevents acting in production by mistake).
- Top bar: logo, global search, system status, notifications, account menu (Profile, MFA, Sign out). Account menu only in top bar.
- **Support-access banner**: when an operator is inside an authorized tenant diagnostic session, a persistent amber banner shows tenant, scope, reason, time remaining and "End session" (Confirmed requirement: scoped, logged, auditable).
- Sidebar: dark, grouped navigation; groups with no visible items are hidden.

---

## 4. RBAC-driven navigation model

### 4.1 Rules
1. Root Console uses **separate platform permissions**; tenant permissions are never a substitute (Confirmed).
2. Platform Super Admin is managed in Root Console, not as a tenant role (Confirmed).
3. Navigation defined once in a shared constant (e.g. `PLATFORM_NAV_GROUPS`, Recommended) and evaluated by the central authorization engine; no role-name checks in UI code (mirrors tenant rule — Recommended).
4. UI hiding is a usability aid; the backend enforces every `/api/v1/platform/*` request.
5. Every privileged action (tenant lifecycle change, entitlement/quota override, support access, sensitive export) is audited (Confirmed).
6. Destructive / lifecycle actions require typed confirmation + reason (Recommended).

### 4.2 Navigation structure (Recommended permission keys)

| Group | Item | Route | Permission |
|---|---|---|---|
| Overview | Platform Dashboard | `/dashboard` | `platform.dashboard.view` |
| Tenants | Tenants | `/tenants`, `/tenants/new`, `/tenants/:id` | `platform.tenant.view` |
| Tenants | Support Diagnostics | `/support` | `platform.support.access` |
| Commercial | Plans | `/plans` | `platform.plan.view` |
| Commercial | Subscriptions | `/subscriptions` | `platform.subscription.view` |
| Commercial | Licenses | `/licenses` | `platform.license.view` |
| Commercial | Entitlements & Quotas | `/entitlements`, `/quotas` | `platform.entitlement.view` |
| Commercial | Usage & Metering | `/usage` | `platform.usage.view` |
| Configuration | Integration Catalog | `/integrations` | `platform.integration_catalog.view` |
| Configuration | Feature Flags & Config | `/config` | `platform.config.view` |
| Operations | System Health | `/health` | `platform.ops.view` |
| Operations | Jobs & Queues | `/jobs` | `platform.ops.view` |
| Operations | Errors & Dead Letters | `/errors` | `platform.ops.view` |
| Administration | Platform Users | `/platform-users` | `platform.user.view` |
| Administration | Platform Roles | `/platform-roles` | `platform.role.view` |
| Administration | Platform Audit Logs | `/audit-logs` | `platform.audit.view` |

### 4.3 Platform roles → visibility (Recommended; only Super Admin is named in docs)

Legend: ● full · ◐ read-only · — hidden

| Nav item | Super Admin | Platform Admin | Billing / Commercial Ops | Support Engineer | SRE / Operations | Auditor (read-only) |
|---|---|---|---|---|---|---|
| Platform Dashboard | ● | ● | ● | ● | ● | ◐ |
| Tenants | ● | ● | ◐ | ◐ | ◐ | ◐ |
| Support Diagnostics | ● | ◐ | — | ● (scoped, time-boxed) | ◐ | ◐ (sessions log) |
| Plans | ● | ◐ | ● | — | — | ◐ |
| Subscriptions | ● | ◐ | ● | ◐ | — | ◐ |
| Licenses | ● | ◐ | ● | — | — | ◐ |
| Entitlements & Quotas | ● | ● | ● | ◐ | — | ◐ |
| Usage & Metering | ● | ● | ● | ◐ | ◐ | ◐ |
| Integration Catalog | ● | ● | — | ◐ | ◐ | ◐ |
| Feature Flags & Config | ● | ● | — | — | ◐ | ◐ |
| System Health / Jobs / Errors | ● | ◐ | — | ◐ | ● | ◐ |
| Platform Users | ● | ◐ | — | — | — | ◐ |
| Platform Roles | ● | — | — | — | — | ◐ |
| Platform Audit Logs | ● | ● | ◐ | ◐ | ◐ | ● |

### 4.4 Action-level rules (Recommended)
- Tenant **suspend / reactivate / deactivate**: `platform.tenant.lifecycle` — Super Admin, Platform Admin.
- Plan version **publish**: `platform.plan.manage` — Super Admin, Billing.
- Entitlement/quota **override per tenant**: `platform.entitlement.override` — requires reason, expiry, audited.
- Support access: `platform.support.access` — requires ticket/reason, tenant scope, read-only by default, time limit, auto-expiry; optionally tenant-admin approval (**Open**).
- Platform user/role management: `platform.user.manage`, `platform.role.manage` — Super Admin only.
- No operator can read tenant credentials or secrets; integration credentials always masked.

---

## 5. Screen inventory — Root Console

**Total: 30 screens** (all Recommended designs derived from Confirmed Root Console scope).

| ID | Screen | Route | Permission |
|---|---|---|---|
| R-00 | App shell (+ support-access banner variant) | — | — |
| R-01 | Sign in | `/login` | public |
| R-02 | MFA verification (mandatory) | `/login/mfa` | public |
| R-03 | Platform Dashboard | `/dashboard` | `platform.dashboard.view` |
| R-04 | Tenants list | `/tenants` | `platform.tenant.view` |
| R-05 | Provision tenant (wizard) | `/tenants/new` | `platform.tenant.create` |
| R-06 | Tenant detail — Overview | `/tenants/:id` | `platform.tenant.view` |
| R-07 | Tenant detail — Subscription & License tab | `/tenants/:id/subscription` | `platform.subscription.view` |
| R-08 | Tenant detail — Entitlements & Quotas tab | `/tenants/:id/entitlements` | `platform.entitlement.view` |
| R-09 | Tenant detail — Usage tab | `/tenants/:id/usage` | `platform.usage.view` |
| R-10 | Tenant detail — Lifecycle & Audit tab | `/tenants/:id/lifecycle` | `platform.tenant.view` |
| R-11 | Tenant lifecycle action dialog (suspend/reactivate/deactivate) | dialog | `platform.tenant.lifecycle` |
| R-12 | Plans list | `/plans` | `platform.plan.view` |
| R-13 | Plan detail & version editor | `/plans/:id/versions/:v` | `platform.plan.manage` |
| R-14 | Subscriptions list | `/subscriptions` | `platform.subscription.view` |
| R-15 | Licenses (grants) | `/licenses` | `platform.license.view` |
| R-16 | Entitlement catalog | `/entitlements` | `platform.entitlement.view` |
| R-17 | Quota definitions | `/quotas` | `platform.entitlement.view` |
| R-18 | Entitlement / quota override dialog | dialog | `platform.entitlement.override` |
| R-19 | Usage & Metering | `/usage` | `platform.usage.view` |
| R-20 | Integration Catalog | `/integrations` | `platform.integration_catalog.view` |
| R-21 | Integration catalog item editor | `/integrations/:provider` | `platform.integration_catalog.manage` |
| R-22 | Feature Flags & Global Config | `/config` | `platform.config.view` |
| R-23 | System Health | `/health` | `platform.ops.view` |
| R-24 | Jobs & Queues (RabbitMQ / workers) | `/jobs` | `platform.ops.view` |
| R-25 | Errors & Dead Letters | `/errors` | `platform.ops.view` |
| R-26 | Platform Users | `/platform-users` | `platform.user.view` |
| R-27 | Platform Roles & Permissions | `/platform-roles` | `platform.role.view` |
| R-28 | Platform Audit Logs | `/audit-logs` | `platform.audit.view` |
| R-29 | Support Diagnostics (request + active session) | `/support` | `platform.support.access` |

(+ shared 403 / 404 / error states — reuse Tenant T-05 pattern with Root styling.)

---

## 6. Screen specifications and Stitch prompts

### R-00 — App shell
```
Using the QmentisAI Root Console design system, create the application shell. 32px environment strip #020617 with "PLATFORM CONSOLE · PRODUCTION". 56px white top bar: "QmentisAI Root" logo, search "Search tenants, users, plans… ⌘K", status "All systems operational" with green dot, bell, avatar "SA". Dark sidebar (#0F172A) with groups: OVERVIEW (Platform Dashboard — active), TENANTS (Tenants, Support Diagnostics), COMMERCIAL (Plans, Subscriptions, Licenses, Entitlements & Quotas, Usage & Metering), CONFIGURATION (Integration Catalog, Feature Flags & Config), OPERATIONS (System Health, Jobs & Queues, Errors & Dead Letters), ADMINISTRATION (Platform Users, Platform Roles, Platform Audit Logs). Active item slate-800 background with violet-600 left bar.
```
RBAC variant:
```
Same shell for a "Billing / Commercial Ops" user: sidebar shows OVERVIEW, TENANTS (Tenants only), COMMERCIAL (all items), ADMINISTRATION (Platform Audit Logs only). CONFIGURATION and OPERATIONS groups are fully absent.
```
Support-access banner variant:
```
Same shell with a persistent amber-600 banner under the top bar: shield icon, "Support session active — Tenant: Acme Corp · Scope: read-only diagnostics · Reason: TKT-4821 · 38 min remaining · All actions are audited", and a button "End session".
```

### R-01 / R-02 — Sign in & MFA
```
Create the Root Console sign-in page: full dark background #020617, centered 400px white card with "QmentisAI Root Console" logo, warning text "Authorized QmentisAI operators only. Activity is monitored and audited.", fields Email and Password, primary violet button "Sign in", "Sign in with company SSO" outline button. Second frame: mandatory MFA step with six-digit code inputs and "Use security key" option.
```

### R-03 — Platform Dashboard
```
Create the "Platform Dashboard". KPI row: Active tenants 142, Trials 18, Suspended 3, MRR placeholder hidden (no prices), Executions (24h) 48,210, Queue backlog 312 (amber), DLQ messages 7 (red), Error rate 0.4%. Row 2: line chart "Executions per hour (24h)" and bar chart "Tenants by plan". Row 3: "Tenants nearing quota" table (tenant, quota, usage bar >90% red), "Recent lifecycle changes" list, "Service health" grid (API, Pipeline worker, Analysis worker, Scan worker, Notification worker, Usage worker, Scheduler, PostgreSQL, Redis, RabbitMQ) with status dots.
```

### R-04 — Tenants list
```
Create the "Tenants" list page. Header button "Provision tenant". Toolbar: search, Lifecycle filter (Provisioning, Trial, Active, Suspended, Deactivated), Plan filter, Region filter. Table: Tenant name + ID (mono), Lifecycle pill, Plan + version, Subscription status, Workspaces, Users, Executions (30d), Quota health (worst meter), Created, row actions (View, Suspend, Open support session). Read-only variant for Support Engineer: no "Provision tenant" button, row actions limited to View and "Request support session".
```

### R-05 — Provision tenant wizard
```
Create a "Provision tenant" wizard with stepper: 1 Organization, 2 Plan & subscription, 3 Entitlements & quotas, 4 Initial admin, 5 Review. Show step 3: inherited entitlements from the selected plan as a table (Entitlement, Plan default, Override value, Override expiry) with SCA, SBOM, SAST, Secret Scanning, Manual DAST, Asset Discovery, AI coding-tool integrations, Max repositories, Max users, Scan executions per month, Concurrent executions. Overrides highlighted violet-50 with "Reason required" input. Right summary card. Footer Back / Continue.
```

> As built 2026-11-13 (`apps/root-console/src/features/tenants/pages/provision-tenant-page.jsx`): three steps, **Tenant** (name, slug, initial status, optional plan), **First administrator** (name, email) and **Review**, inside `WizardLayout` (`@qmentisai/ui`, `docs/design/UX_GUIDELINES.md` section 13; offset 7.5 rem for the environment strip). Plan & subscription and Entitlements & quotas steps are not built: the API accepts only an optional `planVersionId`. Next validates the step's fields (error icon and "(needs attention)" on the step); a server slug conflict (409) or field error returns to the step that holds the field. Verified in headless Chrome at 1280, 1440, 1024, 820 and 390 px: the page does not scroll, header, stepper, summary (>= 1280) and action bar keep their position while the form column scrolls; provisioning succeeded and a duplicate slug returned to step 1 with "This slug is already taken."

### R-06 — Tenant detail (Overview)
```
Create "Tenant detail" for "Acme Corp" (ID mono). Header: lifecycle pill Active, plan chip "Business v3", buttons "Open support session", "Suspend" (amber outline), overflow menu (Deactivate). Tabs: Overview, Subscription & License, Entitlements & Quotas, Usage, Lifecycle & Audit. Overview: org details card (domain, region, created, tenant admin contacts), stats (workspaces 6, repositories 48, pipelines 72, users 62), connected integration types (counts only, no credentials), health of tenant's integrations, recent platform-side events. Note: "Tenant business data (findings, code) is not visible here. Use an authorized support session."
```

### R-07 — Subscription & License tab
```
Create the "Subscription & License" tab of tenant detail: current subscription card (plan, version, term start/end, renewal, status), license grants table (grant ID, type, seats/limits, valid from/to, status), subscription history timeline (plan changes, renewals). Buttons "Change plan" and "Add license grant" for billing users.
```

### R-08 — Entitlements & Quotas tab
```
Create the "Entitlements & Quotas" tab: table with columns Entitlement, Source (Plan / Override), Value, Usage (progress bar with thresholds), Override expiry, Last changed by. Overridden rows marked with violet "Override" badge and expiry date. Button "Add override".
```

### R-09 — Usage tab
```
Create the tenant "Usage" tab: period select, metric cards (Executions, Scan minutes, Manual DAST scans, Storage), stacked bar chart of executions by scan type per day (SCA, SBOM, SAST, Secrets, DAST), table usage by workspace, export CSV.
```

### R-10 — Lifecycle & Audit tab
```
Create the tenant "Lifecycle & Audit" tab: lifecycle state diagram strip (Provisioning → Trial → Active ⇄ Suspended → Deactivated → Pending deletion) with current state highlighted; below, an immutable timeline of lifecycle changes, entitlement overrides and support sessions, each with actor, reason, ticket, timestamp and correlation ID.
```

### R-11 — Lifecycle action dialog
```
Create a destructive confirmation dialog "Suspend tenant Acme Corp": impact list (users cannot sign in, pipelines and scheduled scans paused, webhooks queued/ignored, data retained), Reason select + details textarea (required), ticket reference, "Notify tenant admins" checkbox, type-to-confirm field "Type ACME-CORP to confirm", buttons Cancel and amber "Suspend tenant". Variant for "Deactivate" with red button and data-retention notice.
```

### R-12 — Plans list
```
Create the "Plans" page: cards or table of plans (Starter, Team, Business, Enterprise — names placeholder) with current published version, tenants count, status (Draft / Published / Retired). Note banner "Commercial plan names, prices and quota values are not finalized." Button "Create plan".
```

### R-13 — Plan version editor
```
Create "Plan version editor" for "Business — v4 (Draft)". Version selector with history (v1–v3 published, read-only). Sections: Included entitlements (checkbox list grouped: Scanning, Integrations, Workflow, Reporting), Quotas (input per quota definition with unit), Limits (concurrency, retention days). Diff panel "Changes vs v3". Buttons "Save draft" and "Publish version" with warning "Existing tenants stay on their version until migrated."
```

### R-14 / R-15 — Subscriptions & Licenses
```
Create the "Subscriptions" page: table Tenant, Plan + version, Status pill (Active, Past due, Cancelled, Expired), Term start, Term end, Auto-renew, actions. Second frame "Licenses": table Grant ID (mono), Tenant, Type, Limits, Valid from/to, Status, Issued by; button "Issue license grant".
```

### R-16 / R-17 — Entitlement catalog & Quota definitions
```
Create "Entitlement catalog": table Key (mono e.g. scan.sast), Name, Category, Type (Boolean / Limit), Used by plans, Status. Second frame "Quota definitions": Key, Name, Unit (executions, repositories, users, GB), Reset period (Monthly / None), Enforcement (Hard / Soft with warning at %), Linked entitlement.
```

### R-18 — Override dialog
```
Create a dialog "Override entitlement for Acme Corp": Entitlement select, Current value (from plan), New value, Expiry date (required), Reason textarea (required), Ticket reference. Footer note "This change is audited." Buttons Cancel / Apply override.
```

### R-19 — Usage & Metering
```
Create "Usage & Metering": filters period, plan, tenant. Charts: platform executions by scan type (stacked area replaced by stacked bar), top 10 tenants by usage (horizontal bar). Table: Tenant, quota, used, limit, % bar, status. Panel "Metering pipeline": usage events ingested (24h), aggregation lag, last aggregation run.
```

### R-20 / R-21 — Integration Catalog
```
Create the global "Integration Catalog": table Provider (logo + name), Category (Source control, AI coding tools, Ticketing, Collaboration, Security tools, Cloud, Secrets), Availability (GA / Beta / Disabled), Required entitlement, Tenants using, Adapter version, actions. Second frame "Integration editor" for "Claude Code": availability toggle, release stage select, required entitlement select, capability checklist (verified capabilities only: hooks, events, callbacks), allowed regions, documentation link.
```

### R-22 — Feature flags & global config
```
Create "Feature Flags & Config" with tabs Flags and Global config. Flags table: key (mono), description, state (On/Off/Partial rollout), targeting (all, plans, specific tenants), last changed by, toggle. Editing opens a side sheet with targeting rules and required change reason. Global config tab: grouped key/value settings (retention defaults, default SLA values marked "Configurable — not finalized", rate limits) with read-only lock for non-admins.
```

### R-23 — System Health
```
Create "System Health": status grid cards for API, Pipeline worker, Analysis worker, Scan worker, Notification worker, Usage worker, Scheduler worker, PostgreSQL, Redis, RabbitMQ, Object storage, Socket.IO — each with status dot, latency/throughput sparkline, instances count. Below: incidents list and line charts for API p95 latency and error rate.
```

### R-24 — Jobs & Queues
```
Create "Jobs & Queues": table of RabbitMQ queues (name, consumer worker, depth, rate in/out, oldest message age, consumers, status pill Normal/Backlog). Selecting a queue shows a side panel with throughput chart and recent jobs (message ID mono, event type, tenant ID, correlation ID, attempts, status). Payloads hidden by default; "View payload" requires permission and redacts secrets.
```

### R-25 — Errors & Dead Letters
```
Create "Errors & Dead Letters": tabs Errors and Dead-letter queue. DLQ table: message ID, event type + schema version, tenant, failure classification (Transient / Invalid credentials / Invalid config / Permission denied / Unsupported target), attempts, last error code, first seen. Actions: "Retry" (only for transient), "Discard" (with reason). Errors tab: grouped error codes with counts, affected tenants, sample correlation IDs.
```

### R-26 / R-27 — Platform users & roles
```
Create "Platform Users": table name, email, platform roles (chips: Super Admin, Platform Admin, Billing Ops, Support Engineer, SRE, Auditor), MFA status (must be ✓), last sign-in, status; button "Invite operator". Second frame "Platform Roles": role list left, right a grouped permission matrix with keys like platform.tenant.lifecycle, platform.support.access, platform.entitlement.override; Super Admin role locked.
```

### R-28 — Platform Audit Logs
```
Create "Platform Audit Logs": filters date range, actor, action category (Tenant lifecycle, Entitlement override, Plan publish, Support access, Platform user/role change, Config change, Export), tenant, result. Table: timestamp, actor, action (mono), target tenant, reason/ticket, IP, result, correlation ID. Row opens side sheet with before/after diff. Export button (export itself is audited).
```

### R-29 — Support Diagnostics
```
Create "Support Diagnostics" with two frames. Frame 1 "Request support session": Tenant select, Scope checkboxes (Read-only metadata, Pipeline & execution status, Worker/job logs for tenant, Integration health — credentials never shown), Duration select (15/30/60 min), Reason + ticket (required), "Tenant admin approval required" info line. Button "Start session". Frame 2 "Active & past sessions" table: operator, tenant, scope, started, expires/ended, actions count, status, link to audit trail.
```

---

## 7. Open items

- Platform role set beyond Super Admin (names and permission bundles in §4.3 are Recommended).
- Whether support sessions need tenant-admin approval.
- Billing/invoicing provider (out of scope — no prices shown).
- Plan names, quota values, SLA defaults — remain configurable placeholders.
- Brand/primary colors for both apps.
