# Screens: repositories and GitHub integration

Status: **Draft, for owner review** (nothing is implemented). Companion to `SPEC.md` (same labels: **Confirmed**, **Recommended**, **Open**).

**The screen identifiers are not defined anywhere in this repository.** `docs/TENANT_APP_WIREFRAME_SPEC.md` does not exist (the same gap noted in `access-management/SCREENS.md`), so T-13, T-14, T-22, T-23, T-24 and T-42 below are my **proposed mapping** onto the screens that the design documents do describe. **Open (SPEC Q4): please confirm or correct the mapping.** Sources: `docs/design/TENANT_APPLICATION_DESIGN.md` §3.3/§3.3a (Repositories), §3.14 (Integrations), §3b.2 (Connect Repository), §3b.3 (Repository Details), §3b.5 (Repository tabs); `docs/design/DESIGN_SYSTEM.md` and `UX_GUIDELINES.md` for visual and state rules.

| ID (proposed) | Screen | Route | Route permission | Data | Source |
|---|---|---|---|---|---|
| T-13 | Repositories list | `/repositories` (all workspaces) and `/workspaces/{id}/repositories` | `repository.view` (collection: visible workspaces only) | `GET /repositories` | TAD §3.3, §3.3a |
| T-14 | Connect repository (wizard) | `/workspaces/{id}/repositories/connect` | `repository.connect` in the workspace | `GET /integrations/github/installations`, `GET /workspaces/{id}/repositories/available`, `POST /workspaces/{id}/repositories` | TAD §3b.2 |
| T-22 | Repository detail: Overview | `/repositories/{repositoryId}` | `repository.view` (resource scope) | `GET /repositories/{id}`, later pipeline and finding summaries | TAD §3b.3 |
| T-23 | Repository detail: Settings and access | `/repositories/{repositoryId}/settings` | `repository.update` | `PATCH /repositories/{id}`, `POST .../sync`, `.../disable`, `.../enable`, `DELETE ...` | TAD §3b.5 |
| T-24 | Repository detail: Branches and activity | `/repositories/{repositoryId}/activity` | `repository.view` | `GET .../branches`, `GET .../pull-requests`, delivery/event summary | TAD §3b.5 |
| T-42 | Integrations (GitHub connection management) | `/integrations` and `/integrations/github` | `integration.view` (manage actions need `integration.manage`) | `GET /integrations/github`, `.../installations`, `POST .../start`, `POST .../installations`, `.../refresh`, `DELETE ...` | TAD §3.14 |

Common rules for all six (**Confirmed**, `UX_GUIDELINES.md`/`FRONTEND_ARCHITECTURE.md`): every data view has loading, empty, error and unauthorized states; filters, sorting and the page live in the URL; TanStack Query keys start with the tenant; permission-aware actions through the central engine (disable with a reason, or hide, never by role name); backend enforces; Geist, mono only for identifiers (repository full names, SHAs, ids), Lucide icons, mint only for the primary action; status chips are outlined with icon and text (never color alone).

## T-13 Repositories list
- **Table (TAD §3.3):** Repository (mono full name), Workspace, Provider, Default branch (mono), Pipelines, Connection health, Last event / last scan, Open findings. In v1 the Pipelines, Last scan and Open findings columns show only what exists (the pipeline and finding modules add them), as T-07 did for workspaces.
- **Filters (TAD §3.3):** search, provider (GitHub now; GitLab/Bitbucket disabled and labeled "later"), workspace, health, status; total count. Sort: name, connected date, last event.
- **Primary:** Connect repository (disabled with a reason without `repository.connect` in any workspace). **Row actions:** Open, Sync now (`repository.sync`), Disable/Enable (`repository.toggle`), Settings, Disconnect (typed confirmation, `repository.disconnect`).
- **States:** loading; empty "No repositories yet" with the Connect action or, when GitHub is not linked, a link to Integrations; empty-filtered with Clear filters; error with retry; unauthorized when the caller sees no workspace.

## T-14 Connect repository (wizard)
Follows the shared wizard pattern (TAD §3b: stepper, main card, Summary card, bottom action bar, one mint primary). **Recommended deviations for a GitHub App** (SPEC R-1, Q6): there is no per-repository "manage webhooks" permission or webhook registration; the provider step is a single provider (GitHub) because GitLab and Bitbucket are out of scope.

| Step | Content | Notes |
|---|---|---|
| 1. Provider | Provider cards (GitHub selectable; GitLab and Bitbucket shown disabled, "not available yet"); existing connection chip (for example "GitHub: acme, Active") | Continue disabled until GitHub is selected |
| 2. Authorize | Choose a linked installation, or "Link another GitHub account/organization": opens the GitHub App install page, then a waiting state on return (spinner with the installation being verified) | Requires `integration.manage` to link; otherwise only existing installations are offered. Shows the permissions the App requests (Metadata, Contents, Pull requests: read) and an encryption/credentials note: tokens are never displayed and are short-lived |
| 3. Repositories | Search, organization and visibility filters, table with a selection control (Repository mono, Visibility, Default branch mono, Last pushed, Status: Available or Already connected, disabled), "N selected", select-all on the page | `GET .../available`, paged; outage -> error state with retry |
| 4. Workspace and configuration | Per repository: Workspace (pre-set when started from a workspace), Owner (select), Description; bulk "Assign all to workspace" | Only workspaces where the caller has `repository.connect` |
| 5. Default branch and access | Detected default branch (override is Open SPEC Q), provider permissions Granted/Missing (read-only list from the installation), repository access inside QmentisAI: Inherit workspace access or Restrict to groups | Group restriction semantics Open (SPEC Q12) |
| 6. Validation | Repository-by-check matrix: Credentials, Repository metadata, Installation covers the repository, Test delivery, Signature verification; states Succeeded, Running, Pending | Replaces "Webhook registration" |
| 7. Success | "N repositories connected", per-repository health chips, next steps: Create pipeline (primary, once the pipelines module exists; otherwise View repositories), Connect more | |
| 8. Failure and recovery | Partial result ("2 of 3 connected"); failed repository with stable error code, plain-language cause, retryable or not, recovery steps, correlation ID (mono, copyable); Retry validation (primary), Edit permissions (link to GitHub), Continue with the connected repositories, Copy diagnostics | Error codes: `CONFLICT` (`repository_already_connected`), `QUOTA_EXCEEDED`, `ENTITLEMENT_REQUIRED`, `PROVIDER_UNAVAILABLE` |

## T-22 Repository detail: Overview
- **Header (TAD §3b.3):** repository name (mono), connection chip, provider, workspace link, description, default branch, owner, last sync, health. Actions: Sync now (`repository.sync`), a menu with Disable and Disconnect. "Run scan" (mint primary in the design) is **not shown** until the pipelines and executions modules exist.
- **Tabs:** Overview, Pipelines, Executions, Findings, Branches and Activity, Settings and Access (TAD §3b.3). In v1 only Overview, Branches and Activity, and Settings and Access are enabled; the others are listed as "planned" (the placeholder pattern already used in the app).
- **Overview content now:** summary strip (Webhook/installation health, Last event, Last sync, Pipelines: "0, planned"), repository information (full name, id, visibility, default branch, archived, installation account), recent events (last deliveries summarized: type, time, outcome), health with the failure reason and recovery steps (SPEC §6.4). Pipelines, executions, findings and branches/commits panels arrive with their modules.
- **States:** loading skeleton; 404 not-found state for an absent or not visible repository (identical); error with retry; degraded/error health banner with the recovery action.

## T-23 Repository detail: Settings and access
- **Sections (TAD §3b.5):** General (display name, description, owner, workspace read-only, default branch read-only in v1), Access (inherit or restrict to groups; needs `repository.manage_access`), Integration (installation account, permissions granted, last delivery time and outcome; "secret rotation" from the design does not exist for an App: the webhook secret is platform-level, so the control is omitted), Sync (Sync now; frequency Open SPEC Q21), State (Disable/Enable), Danger zone (Disconnect with the repository full name typed; the server checks it too).
- **Behavior:** Save changes (mint primary) with an unsaved-changes note; actions disabled with a reason when the permission is missing; disconnect explains that history is kept and the repository can be reconnected.
- **States:** loading, error, unauthorized (without `repository.update` the page shows the unauthorized state, reading stays on T-22).

## T-24 Repository detail: Branches and activity
- **Branches table (TAD §3b.5):** Branch, Protection, Last commit SHA (mono), Updated, Scan state (empty until pipelines exist). **Pull requests table:** number, title, author, source -> target, status, scan result (empty until pipelines exist). Data is read live from GitHub through the API with a short cache (SPEC REQ-020, Q16); titles are treated as untrusted text and rendered escaped.
- **Activity:** recent webhook-driven events for this repository (Time, Event, Ref/PR, Outcome), filter by event type and date range, pagination. The Export from the design is Planned.
- **States:** loading; empty "No branches or pull requests"; provider unavailable (stale-data notice with retry); error; unauthorized.

## T-42 Integrations
- **Layout (TAD §3.14):** catalog grouped by category (Source control first). Cards: name, health chip, scope, last sync. Only **GitHub** is connectable; the other categories are listed as "not available yet" without implying identical capabilities (IA, TAD §3.14).
- **GitHub detail (`/integrations/github`):** installations table (Account, Type, Repository selection, Status chip, Repositories, Linked by, Linked at, health reason), actions Link account (primary, `integration.manage`), Refresh, Unlink (typed account login). The page explains what unlinking does (repositories are disconnected and events stop; the App stays installed on GitHub until removed there).
- **States:** App not configured on the platform (clear message for admins, "ask the platform administrator"), loading, empty (no installations: explains linking), error, unauthorized (needs `integration.view`; actions need `integration.manage`). Route registered with the existing nav item `integrations`; the workspace-level `workspace-integrations` item stays unimplemented.

## Navigation and permissions summary
Existing items: `repositories` (workspace scope, `repository.view`), `integrations` (tenant scope, `integration.view`); both flip to `implemented` when their screens ship (`packages/shared/src/navigation.js`).

## Open items for review
Screen-ID mapping (SPEC Q4); wizard deviations for the GitHub App (Q6); default-branch override (this file and SPEC Q); group restriction UI (Q12); unlink semantics (Q10); branches/PR source (Q16).
