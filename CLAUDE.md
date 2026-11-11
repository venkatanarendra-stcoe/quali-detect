# CLAUDE.md — QmentisAI standing instructions

`docs/` is the source of truth. Read the relevant docs before changing anything; `AGENTS.md` and `docs/ai-development/AGENT_INSTRUCTIONS.md` carry the shared agent rules. Never claim a command ran unless you ran it.

## Product
QmentisAI is an AI-native security engineering workflow platform (repos → scans → findings → human review → approval → remediation), not a chatbot.
Hierarchy: **Tenant → Workspace → Repository → Pipeline → Execution → Findings**. One repo has N pipelines; each matching event creates one execution per pipeline; finding identity is per pipeline (never merged). Root Console (platform admin) and Tenant App are separate frontends with separate permission models.

## Hard constraints (docs/README.md, docs/technical/TECH_STACK.md)
- JavaScript ES Modules only: `.js` / `.jsx`, no TypeScript, no CommonJS. JSDoc on public functions and contracts; Zod at API, webhook, message and env boundaries.
- Backend Fastify (never NestJS); Prisma + PostgreSQL; Redis (cache/locks/rate limit); RabbitMQ (durable jobs); Socket.IO (authorized realtime only); Pino; OpenAPI.
- Frontend React + Vite + shadcn/ui + Tailwind + React Router + TanStack Query/Table + Zustand + React Hook Form + Recharts + Lucide + Sonner.
- pnpm workspaces + Turborepo; ESLint + Prettier; pinned dependency versions, commit the lockfile, justify every new dependency.
- Out of scope now: Docker, Docker Compose, Kubernetes, deployment/CI config, test-case structures. Secure engineering and review still apply.

## Tenant isolation (docs/architecture/TENANT_ISOLATION.md, ADR-003)
- Never query a tenant-owned record by ID alone; include trusted tenant scope and validate workspace/repository/pipeline parent-child links.
- Never trust `tenantId` from request bodies or messages; revalidate resource ownership in workers.
- Tenant/resource scope in cache keys, locks, queue messages, storage paths, exports and Socket.IO rooms; no sensitive payloads to broad rooms.
- Platform (Root Console) access uses separate platform permissions; cross-tenant support access is scoped and audited.

## Backend (docs/architecture/BACKEND_ARCHITECTURE.md, API_STANDARDS.md)
Modular monolith by domain + separate worker entry points. Module layout: `routes/ controllers/ services/ repositories/ schemas/ policies/ events/ listeners/ mappers/ constants/ index.js`. Thin routes; Prisma only inside repositories; DTO mappers (never expose Prisma models); transactions for multi-record changes.
Request lifecycle: parse → validate → authenticate → tenant/resource context → authorize → tenant status/entitlement → service → persist → durable event → standard response. Unauthenticated input must never choose tenant context.
API: REST under `/api/v1` (platform under `/api/v1/platform`); Zod on params/query/body; pagination, explicit filter/sort; idempotency keys for side-effecting ops.
Envelope: success `{ success: true, data, meta: { correlationId } }`; error `{ success: false, error: { code, message }, meta: { correlationId } }`. Stable machine codes; never leak stacks, SQL, secrets. Events: versioned envelope, validated at producer and consumer, idempotent handlers, outbox for DB+publish atomicity.

## Frontend (docs/architecture/FRONTEND_ARCHITECTURE.md, design/)
- Feature folder: `components/ pages/ hooks/ services/ schemas/ stores/ constants/ index.js`; keep code in features, components small.
- TanStack Query owns server state; Zustand only client/UI state; URL params for filters/pagination. Every data view has loading, empty, error, unauthorized states.
- RBAC: permissions are `resource.action`. **Navigation is defined once in `@qmentisai/shared` and evaluated by the central authorization engine — never check role names in UI code.** UI hides/disables for usability only; the backend enforces.
- Follow `docs/design/DESIGN_SYSTEM.md` tokens exactly (Geist Sans, mono only for identifiers, Lucide icons, mint only for primary action/active nav/focus, severity colors independent).

## Status rule
Docs label decisions **Confirmed** (agreed), **Recommended** (proposal) or **Open** (needs input). Treat only Confirmed/Accepted as requirements. Never promote Recommended/Open items; present options with a recommendation (`docs/decisions/OPEN_DECISIONS.md`). Ask before changing an approved decision or ADR; if docs conflict, say so and ask.
Layout (decided by the user in Phase 1): `apps/{api,workers,tenant-web,root-console}` and `packages/{shared,contracts,db,infra,ui,config}` (`infra` = server-only Redis/RabbitMQ abstractions); `AGENT_INSTRUCTIONS.md` (`apps/backend`) and ADR-006 (`backend/{api,workers}`) are superseded for layout and still need a doc update. Several docs (ADR-006 mock-first, `AUTHORIZATION.md`, `FRONTEND_ARCHITECTURE.md` navigation tables, `PROGRESS_TRACKER.md`) describe a prototype that was deleted; the repo now holds the Phase 1 skeleton plus docs.

## Workflow
One module at a time: write/complete its spec from `docs/technical/MODULE_SPECIFICATION_TEMPLATE.md` (specs under `docs/modules/`), plan (files, DB/API/event changes, authz and tenant impact, risks), implement incrementally, then report files changed, checks actually run, limitations, open decisions. Update docs in the same work item when behavior changes; record changes in `docs/development/PROGRESS_TRACKER.md`.

## docs/ index
- `README.md` — how to use the pack, status labels, key constraints
- `ai-development/AGENT_INSTRUCTIONS.md` — common agent rules (stack, invariants, security, coding, scope)
- `ai-development/TOOL_ADAPTERS.md` — how each AI tool should point back to docs
- `architecture/OVERALL_ARCHITECTURE.md` — modular monolith, workers, data ownership, diagram
- `architecture/BACKEND_ARCHITECTURE.md` — Fastify modules, domains, request lifecycle
- `architecture/FRONTEND_ARCHITECTURE.md` — frontend stack, feature layout, state rules, nav layouts (stale in parts)
- `architecture/TENANT_ISOLATION.md` — enforcement points and query/cache/event rules
- `architecture/WORKER_ARCHITECTURE.md` — worker types, job envelope, retries, cancellation
- `architecture/INTEGRATION_ARCHITECTURE.md` — provider adapters, webhooks, credential security
- `architecture/AUTHORIZATION.md` — RBAC model, permission matrix, navigation rules (prototype notes stale)
- `decisions/ADR-001-JAVASCRIPT.md` — JavaScript ES Modules everywhere
- `decisions/ADR-002-MODULAR-MONOLITH.md` — modular monolith + separate workers
- `decisions/ADR-003-TENANT-ISOLATION.md` — isolation enforced at all layers
- `decisions/ADR-004-FINDING-IDENTITY.md` — findings independent per pipeline
- `decisions/ADR-005-UI-STACK.md` — React, Vite, shadcn/ui, Tailwind for both apps
- `decisions/ADR-006-REPOSITORY-LAYOUT-AND-CODE-FIRST-UI.md` — layout, code-first UI, pinned versions (mock-first part stale)
- `decisions/OPEN_DECISIONS.md` — unresolved business/technical decisions; do not guess
- `design/DESIGN_SYSTEM.md` — tokens, mint rules, components, icons
- `design/UX_GUIDELINES.md` — layout, navigation, tables, states, accessibility
- `design/TENANT_APPLICATION_DESIGN.md` — tenant screen specs and flows
- `design/ROOT_CONSOLE_DESIGN.md` — Root Console cues, navigation, screens
- `design/STITCH_WORKFLOW.md` — Stitch QA/approval process (Stitch generation is suspended)
- `design/STITCH_SCREEN_REGISTRY.md` — append-only record of Stitch screens and approvals
- `development/AI_DEVELOPMENT_WORKFLOW.md` — plan/implement/report protocol for agents
- `development/CODING_STANDARDS.md` — naming, JSDoc, validation, dependency policy
- `development/PROGRESS_TRACKER.md` — workstream status (history is stale)
- `modules/README.md` — module spec order; one folder per module
- `product/PROJECT_CONTEXT.md` — product, hierarchy, roles, workflow, principles
- `product/PRODUCT_REQUIREMENTS.md` — goals, scope, functional areas, NFRs
- `product/FEATURE_CATALOG.md` — scope catalog of tenant and Root Console features
- `product/GLOSSARY.md` — canonical terms for code, API and UI
- `technical/TECH_STACK.md` — approved stack and language rules
- `technical/API_STANDARDS.md` — routes, request rules, envelopes, errors
- `technical/DATABASE_DESIGN.md` — entity groups, modeling and Prisma rules
- `technical/EVENT_CONTRACTS.md` — event envelope, naming, reliability/outbox
- `technical/SECURITY_GUIDELINES.md` — authn/z, secrets, webhooks, untrusted input, audit
- `technical/IMPLEMENTATION_PLAN.md` — recommended phase order
- `technical/MODULE_SPECIFICATION_TEMPLATE.md` — template for each module spec
- `technical/ADR_TEMPLATE.md` — template for new ADRs
