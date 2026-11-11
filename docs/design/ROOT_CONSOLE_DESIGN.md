# Root Console Design

**Status:** Direction documented — no Stitch screens generated yet (deferred until the Tenant Application direction is complete).
**App:** `apps/root-console` (foundation implemented 2026-11-11: shell, environment strip, login + mandatory MFA (mock), navigation, support-access banner component; all modules below are placeholders). `docs/ROOT_CONSOLE_WIREFRAME_SPEC.md` does not exist in this repository, so this document and `DESIGN_SYSTEM.md` were the source. Stitch project: `projects/7652438332940652451` ("QmentisAI Root Console"), currently empty.
**References:** `DESIGN_SYSTEM.md`, `UX_GUIDELINES.md`, `STITCH_WORKFLOW.md`, `TENANT_APPLICATION_DESIGN.md`.

The Root Console uses the same tokens, components and shell proportions as the Tenant Application, except for the Root theme below (violet accent, always-dark sidebar; decision recorded in `DESIGN_SYSTEM.md` §7). It must not share business navigation or permission models with it (FRONTEND_ARCHITECTURE.md). Platform authorization is separate from tenant roles (ADR-003).

---

## 1. Context cues (the only intended differences)

| Cue | Spec |
|---|---|
| Environment tag | A persistent "PLATFORM" label in the top bar, neutral outlined chip (not mint, not red) |
| No workspace switcher | The top bar shows breadcrumb and tenant context only when drilling into a tenant |
| Tenant drill-in banner | When viewing a tenant, a bar under the top bar names the tenant and the access reason; cross-tenant support access is scoped, time-limited and audited |
| Sidebar header | "QmentisAI Platform" wordmark line |
| Destructive actions | Typed confirmation (tenant name) for suspend, deactivate and entitlement removal |

Typography, neutrals, status chips and severity rules are identical to the Tenant Application. The accent is **violet** instead of mint (same usage rules: primary action, active navigation, focus, links) and the sidebar is dark in both themes (`packages/ui/src/root-theme.css`).

| Added cue | Spec |
|---|---|
| Environment strip | 24 px strip across the top of every screen, including sign-in, naming the environment (`VITE_ENVIRONMENT`: Development neutral, Staging warning, Production danger; unknown values are treated as Production). Text, not color alone |
| Sign-in | Platform sign-in is two steps: password, then a **mandatory** verification code. The server withholds all platform data until MFA is complete (see `docs/AUTHORIZATION.md` §16); the mock verifier uses `MOCK_PLATFORM_MFA_CODE` |
| Support-access banner | `SupportAccessBanner` (active, expiring in the last 10 minutes, expired as an alert). Presentational only: it is rendered under the top bar once support-access grants exist; the server enforces grants |

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
