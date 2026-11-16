# Tenant Application Design

**Status:** Final direction — revision 3. Dashboard approved; remaining screens in design.
**App:** `apps/tenant-web` (foundation implemented 2026-11-11; the shell follows `docs/architecture/FRONTEND_ARCHITECTURE.md`, which supersedes the flat sidebar in §1 below).
**References:** `DESIGN_SYSTEM.md` (tokens, statuses), `UX_GUIDELINES.md` (layout, behavior), `STITCH_WORKFLOW.md` (how references are produced).

Role names are those in `PROJECT_CONTEXT.md`: Admin, Manager, Lead, Security Analyst, Dev Lead, Developer, Guest / Viewer. **Permissions below are indicative.** No role-permission matrix exists yet, and the backend enforces every action.

---

## 1. Shell and navigation

Identical on every screen (see the approved dashboard).

- **Sidebar (240 px):** Overview · *Engineering:* Workspaces, Repositories, Pipelines, Executions, Scan History · *Security:* Findings, Security Reviews, Approvals, Remediation, Policies, Reports · *Administration:* Users, Groups, Roles & Permissions, Integrations, Audit Logs · footer: Settings, Docs, user.
- **No top bar** (removed 2026-11-16, owner decision, Confirmed): the sidebar holds the logo, organization / workspace switcher, and navigation ending in the "You" group (Account, Settings (own page `/my-settings`: Appearance / Preferences), Notifications with badge (normal item below Settings, opens the drawer), then Sign out; amended 2026-11-17, owner decision, Confirmed: Settings is not inside Account and Notifications is not at the top). Revised 2026-11-16 (Confirmed): no global search trigger, no bottom-pinned account block. Theme and accent live under Settings > Appearance.
- **Counts** appear only on Findings, Security Reviews and Approvals (items needing action).
- Hierarchy for breadcrumbs: Tenant / Workspace / Repository / Pipeline / Execution.
- Settings opens a sub-navigation: Organization, Account, Authentication & SSO, Notifications, API & Developer, Usage & Consumption, Data Governance.
- "Approvals" is the Lead Approval screen; "Security Reviews" is the analyst TP/FP queue (see UX_GUIDELINES §4.4).

## 2. Common rules for every module

- Page template per UX_GUIDELINES §3.2 (list, detail, wizard, queue).
- States to design for every data view: loading skeleton, empty (no data), empty (no results), error with correlation ID, unauthorized, success, degraded.
- One mint primary action per screen. Severity pills and status chips from `DESIGN_SYSTEM.md` §2.2, §10.
- Tables: severity or name first, row actions last, filters in URL, drawer for quick view.
- Pipeline-scoped findings: never merge findings across pipelines; cross-pipeline similarity is a "Related findings" link list.

## 3. Screen specifications

### 3.1 Overview (approved)
Reference: Stitch screen `e4c2f0775e084cd6b019d67597359b7a`. Five metric cards (Critical open, High open, SLA breaches, Awaiting approval, Pipeline success), open-findings trend, severity distribution, Needs attention table (Severity, Finding, Pipeline, Status, SLA), Recent executions. Primary action: Run scan.

### 3.2 Workspaces
- **Purpose / users:** manage workspaces. Admin, Manager (create/edit); others read scoped.
- **Table:** Name, Repositories, Pipelines, Members, Open findings (Critical/High counts), Last activity, Status.
- **Primary:** Create workspace. **Secondary:** archive, manage members.
- **Filters:** search, status.
- **Detail** (tabs): Overview, Repositories, Members, Policies. **Next:** Repositories filtered by workspace.

### 3.2a Workspace details — approved reference and implementation requirements
Approved reference: Stitch screen `389bb91de5c04c8aaa0b65af87734bba` (Overview tab). Layout: header (breadcrumb, name, Active chip, description, meta row, Manage access, Edit workspace, More actions), a four-segment summary strip, six tabs (Overview, Repositories, Pipelines, Members & Groups, Policies, Activity), a left column of Repositories, Pipelines, Members & Access and Recent activity, and a right column of Workspace information and Security policies (inherited, locked and dimmed; workspace overrides, editable, stricter-only).
Implementation requirements accepted with the approval: (1) the pipeline Scan types column shows the full value without truncation; (2) tabs are keyboard-accessible and focusable with a visible focus ring; (3) policy edit and workspace ID copy controls are at least 24×24px. Also implement sidebar count badges as outlined boxes, keep at least 8px between a label and an adjacent pill, and provide loading, empty and error states.

### 3.3 Repositories
- **Users:** Admin, Manager, Dev Lead.
- **Table:** Repository (mono), Provider, Default branch, Pipelines, Connection health, Last scan, Open findings.
- **Primary:** Connect repository (wizard: provider → repository → webhook/permissions → review). **Secondary:** sync, disconnect (typed confirmation).
- **Filters:** provider (GitHub, GitLab, Bitbucket), workspace, health.

### 3.3a Repositories — approved reference notes
Approved reference: Stitch screen `8d39a79572664db28cecd26eeebf992d`. Layout: page header with one primary action (Connect repository), a filter bar (search, Provider, Workspace, Health, total count), one table card (Repository, Workspace, Provider, Default branch, Pipelines, Connection, Last scan, Open findings, row actions) and an in-card pagination row. Connection states: Healthy, Degraded, Disconnected, Not connected (`DESIGN_SYSTEM.md` §10). Frontend notes: "None" findings text is muted `#7B858C`; the row-actions menu offers Sync and Disconnect (typed confirmation); provide loading, empty and error states; use a proper Bitbucket mark; use the canonical sidebar icons in `DESIGN_SYSTEM.md` §11.

### 3.4 Pipelines
- **Users:** Admin, Manager, Lead.
- **Table:** Pipeline, Repository, Triggers, Scan types (SCA, SBOM, SAST, Secret Scanning; DAST and Asset Discovery as manual), Last execution, Schedule, Status.
- **Primary:** Create pipeline (stepper: repository, triggers, scan selection, review). **Secondary:** run now, pause, edit.
- **Detail** (tabs): Overview, Executions, Findings, Configuration. A repository may have several pipelines; each has its own history and finding identity.

### 3.5 Pipeline execution details
- **Users:** Developer and above; Viewer read-only.
- **Shows:** header (status chip, trigger, branch, commit SHA, duration), scan-task timeline with per-task state, redacted terminal pane (mono), result counts by severity, linked findings.
- **Primary:** Re-run. **Secondary:** Cancel (running), download report.
- **States:** Running, Cancelling, Failed (retryable vs non-retryable explanation).

### 3.6 Executions and Scan History
- **Table:** Execution, Pipeline, Trigger, Scan types, Status, Started, Duration, New findings.
- **Filters:** status, pipeline, trigger, date range. Scan History adds scan type and per-scan outcome. Row opens execution details.

### 3.7 Findings
- **Users:** Security Analyst, Lead, Dev Lead, Developer (scoped), Viewer.
- **Table:** Severity, Finding, Pipeline, Status, SLA (same columns as dashboard), plus Assignee, First seen.
- **Filters:** severity, status (§10 labels), scan type, pipeline, SLA state, assignee.
- **Bulk:** assign, export. **Next:** Finding details.

### 3.8 Finding details
- **Header:** severity, title, status chip, SLA, fingerprint (mono, copy).
- **Tabs:** Overview, Evidence, History, Comments.
- **Shows:** evidence blocks with redaction, AI assessment with provenance tag, human decisions with actor, time and reason, related findings (links only), recurrence.
- **Primary:** Record decision (TP/FP). **Secondary:** assign, suppress, accept risk (each requires a reason).

### 3.9 Security Reviews (queue)
- **Users:** Security Analyst. Split view: queue left, detail right. **Shows:** age, severity, AI assessment, evidence summary. **Primary:** Submit decision (TP/FP with reason). **Secondary:** claim, reassign.

### 3.10 Approvals (Lead Approval)
- **Users:** Lead. **Shows:** pending decisions with analyst rationale and evidence. **Primary:** Approve. **Secondary:** Reject (reason required), request changes. Confirmation dialog on every decision.

### 3.11 Remediation
- **Users:** Developer, Dev Lead. **Shows:** assigned findings, fix guidance, linked PR or ticket, verification status. **Primary:** Mark ready for verification. Status remains "Awaiting Verification" until a covering scan confirms.

### 3.12 Policies
- **Users:** Admin, Manager, Lead. **Table:** Policy, Scope, Rule summary, Enforcement, Status. **Primary:** Create policy. Includes SLA and suppression policies (values are open decisions and are configured, not hard-coded).

### 3.13 Reports
- **Shows:** report templates, generated reports with status, schedule. **Primary:** Generate report. **Secondary:** schedule, download, export. Exports are audited.

### 3.14 Integrations
- **Layout:** catalog grouped by category (Source control, AI coding tools, Ticketing, Collaboration, Security tools, Cloud, Secrets). Card: name, health chip, scope, last sync. **Primary:** Connect. Capability and operations per provider must be verified before design is finalized per card; do not imply identical capabilities.

### 3.15 Users, Groups, Roles & Permissions
- **Users:** table with role, groups, status, last active; invite flow. **Groups:** members and role assignments (group membership alone grants no permissions). **Roles & Permissions:** built-in and custom roles, permission matrix, workspace-specific assignments. Last-tenant-admin invariant is enforced and explained in the UI.

### 3.16 Audit Logs and Settings
- **Audit Logs:** time, actor, action, resource, outcome, correlation ID; filters; export. **Settings:** Organization, Account, Authentication & SSO, Notifications, API & Developer, Usage & Consumption, Data Governance.

---

## 3b. Workspace and repository flows: requirements (added 2026-11-09)

These specs are the requirements checklist (check D in `STITCH_WORKFLOW.md` §6.3) for the screens below. All sample data is illustrative. Provider authorization and webhook mechanisms shown are **illustrative and differ per provider on purpose**; real capabilities must be verified per adapter (`INTEGRATION_ARCHITECTURE.md`). Permissions are indicative until a role matrix exists.

**Shared wizard pattern.** Page header (breadcrumb, title, one-line subtitle), a horizontal stepper strip (numbered steps encode a real sequence: completed step = check icon, current step = `#F4F7F8` text with a 2px `#F4F7F8` underline, upcoming = muted; never mint), a main form card, a right-hand Summary card (values entered so far), and an action bar pinned to the bottom of the main area (Cancel, Back, one mint primary). Inputs are dark (`#080A0D`, `#68737C` border); selection controls (radio, checkbox) are neutral, never mint; inline validation messages are shown.

### 3b.1 Create Workspace (4 steps) — Admin, Manager
1. **Details:** name (required, with an inline "Name available" success check), description, owner (user picker), business unit (select), generated workspace identifier (mono, read-only). Summary: name, owner, business unit, status "Draft".
2. **Members & access:** owner pre-added as Admin (locked row); add members by search (name or email); groups (add group with a workspace role); table: Member, Email, Workspace role (select: Admin, Manager, Lead, Security Analyst, Dev Lead, Developer, Guest / Viewer), Source (Direct or via group), Access (Active, Invited), remove. Group membership alone grants no permission; the role assignment does.
3. **Policies:** "Inherited from tenant" (locked, dimmed, no edit control, tag "Tenant"): mandatory scans, Lead approval for Critical findings, suppression requires a reason, tenant severity floor. "Workspace-specific configuration" (editable, tag "Workspace", stricter-only helper text): fail pipeline at severity, security review required from severity, Lead approval required from severity, additional scan types (SBOM; DAST and Asset Discovery are manual-only).
4. **Review & create:** read-only sections (Details, Members & roles, Policies) each with an Edit link back to its step; a "What happens on creation" note (workspace becomes Active, owner is Admin, invitations are sent); Create workspace (mint primary), Back, Cancel.

### 3b.2 Connect Repository (wizard; stepper: Provider, Authorize, Repositories, Configure, Validate; then a result)
1. **Provider selection:** three provider cards (GitHub, GitLab, Bitbucket) with a different authorization summary each; existing connections shown with a status chip (for example GitHub connected as "acme", GitLab and Bitbucket not connected); Continue disabled until one is selected.
2. **Authorize and configure credentials** (one screen per provider, because mechanisms differ): **GitHub** app installation (select account or organization, requested permissions list, Authorize button, waiting-for-authorization loading state); **GitLab** access token (instance URL, token field masked, required scopes, Test connection with result state); **Bitbucket** OAuth consumer (workspace slug, consumer key, consumer secret masked, required permissions, Test connection). Credentials are never displayed after saving; an encryption note is shown.
3. **Repository selection:** search, organization or group filter, visibility filter, table with a selection control per row (Repository mono, Visibility, Default branch mono, Last pushed, Status: Available or Already connected, which is disabled), "N selected" count, select-all.
4. **Workspace assignment and configuration:** per selected repository: Workspace (select), Repository owner (select), Description (optional); bulk "Assign all to workspace".
5. **Default branch and permissions:** per repository default branch (detected value, overridable); QmentisAI permissions on the provider (Required: read code and metadata, read pull requests, manage webhooks; Optional: write status checks) shown as Granted or Missing; repository access inside QmentisAI (Inherit workspace access, or Restrict to selected groups).
6. **Validation:** a repository-by-check matrix (Credentials, Repository metadata, Webhook registration, Test event delivery, Signature verification) with states Succeeded, Running, Pending; overall progress; Cancel.
7. **Success:** "N repositories connected", per-repository Healthy chips with webhook status; next steps (Create pipeline primary, View repositories, Connect more).
8. **Failure and recovery:** partial result ("2 of 3 connected"); the failed repository with a stable error code, plain-language cause, whether it is retryable, recovery steps, correlation ID (mono, copyable); actions: Retry validation (primary), Edit permissions, Continue with the connected repositories, Copy diagnostics.

### 3b.3 Repository Details — full view (tabs: Overview, Pipelines, Executions, Findings, Branches & Activity, Settings & Access)
Header: repository name (mono), connection chip, provider, workspace link, description, default branch, owner, last sync, health; actions: Run scan (mint primary), Sync now, a menu with Disable and Disconnect (typed confirmation). Overview: summary strip (Pipelines, Open findings, Last scan, Webhook), Pipelines (status), Recent executions and scan history, Security findings summary (by severity), Branches, commits and pull requests (recent), Integration and webhook health, Repository information.

### 3b.4 Workspace tabs (same header and tab bar as Workspace Details)
- **Members & Groups:** members table (Member, Email, Role, Groups, Access, Added, row actions), groups table (Group, Members, Workspace role, Added), Add members (mint primary), Add group.
- **Policies:** inherited tenant policies (locked), workspace overrides (Policy, Tenant minimum, Workspace value, Stricter status, Updated, edit), mandatory scan requirements, severity thresholds, review and approval requirements; Add override (mint primary).
- **Activity:** filter bar (event type, actor, date range), activity table (Time, Actor, Event, Resource, Outcome), pagination, Export (outline). Event types: workspace creation or update, repository connection, pipeline configuration change, member and role change, policy update.

### 3b.5 Repository tabs (same header and tab bar as Repository Details)
- **Settings and Access:** General (display name, description, owner, workspace, default branch), Access (users and groups with role), Webhook and integration (events received, secret rotation, last delivery), Sync (frequency), State (Disable repository), Danger zone (Disconnect repository with typed confirmation); Save changes (mint primary) with an unsaved-changes note.
- **Branches and Activity:** branches table (Branch, Protection, Last commit SHA mono and message, Author, Updated, Scan state), commits list, pull requests table (number, title, author, source to target, status, scan result).
- **Security Overview:** open findings by severity, by scan type (SAST, SCA, SBOM, Secret Scanning), by lifecycle status, trend (neutral line, not mint), top findings table (Severity, Finding, Pipeline, Status, SLA), scan coverage note (an incremental scan never marks a finding fixed).

## 4. Stitch screen registry (summary)

Authoritative records, file IDs, validation results, defects, corrections and history are in `STITCH_SCREEN_REGISTRY.md`. Process and approval rules are in `STITCH_WORKFLOW.md` §6.

| # | Module | Current screen ID | Status |
|---|---|---|---|
| 1 | Overview | `e4c2f0775e084cd6b019d67597359b7a` | **Approved** (manual, frozen) |
| 2 | Workspaces (list) | `db295afd8820481fa92a28227c3b700f` | Generated – Needs Review |
| 2a | Workspace details (Overview tab) | `389bb91de5c04c8aaa0b65af87734bba` (earlier versions: `4f79b452…`, `998d283f…`, `0b5b35fc…`) | **Approved** (manual, 2026-11-09; frozen; implementation requirements in §3.2a) |
| 3 | Repositories | `8d39a79572664db28cecd26eeebf992d` (initial: `c48d5fbe…`) | **Approved** (automatic, 2026-11-09; frozen; notes in §3.3a) |
| 4 | Pipelines | — | Planned |
| 5 | Pipeline execution details | — | Planned |
| 6 | Scan History | — | Planned |
| 7 | Findings | — | Planned |
| 8 | Finding details | — | Planned |
| 9 | Security Reviews | — | Planned |
| 10 | Approvals | — | Planned |
| 11 | Remediation | — | Planned |
| 12 | Policies | — | Planned |
| 13 | Reports | — | Planned |
| 14 | Integrations | — | Planned |
| 15 | Users, Groups, Roles | — | Planned |
| 16 | Audit Logs and Settings | — | Planned |

The detailed defect lists for rows 2 and 2a (previously in this table) were moved unchanged in substance to the registry.

## Navigation correction (two layouts) and workspace Dashboard

Superseding the earlier single sidebar: the Organization layout (Organization Overview, Workspaces, Administration) and the Workspace layout (workspace switcher; Workspace, Security and Workspace Administration groups) are specified in `docs/architecture/FRONTEND_ARCHITECTURE.md`. The sidebar has no account/profile area; the top bar holds the single account control. The workspace page is named **Dashboard** and offers a mutually exclusive Chart view and Table view. Designs for modules that are not built (Executions, Findings, Reviews, Approvals, Remediation, Reports) keep their navigation entries hidden until implemented.
