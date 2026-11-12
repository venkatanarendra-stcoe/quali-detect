# QmentisAI — Instructions for AI Coding Agents

These instructions apply to all AI coding tools working in this repository.

## 1. Source of truth

Read the relevant documents under `docs/` before implementing or changing product behavior.

Priority:
1. Explicitly approved product decisions and ADRs.
2. Approved architecture and module specifications.
3. Actual existing code and migrations.
4. Recommendations in documentation.
5. Your own suggestions.

If documents conflict, do not silently choose. Identify the conflict and ask for a decision or record a proposed resolution.

## 2. Approved technology

- JavaScript ES Modules only.
- Node.js + Express 5 backend (ADR-007).
- React + Vite frontends.
- shadcn/ui + Tailwind CSS.
- PostgreSQL + Prisma.
- Redis for cache and coordination.
- RabbitMQ for durable asynchronous messaging.
- Socket.IO for authorized real-time updates.
- pnpm workspaces + Turborepo.

Do not introduce TypeScript, NestJS or an alternative framework without an accepted architecture decision.

## 3. Application boundaries

- `apps/backend` (superseded: now `apps/api`): API and domain modules (Express 5 per ADR-007; migrated, Fastify is gone).
- `apps/tenant-web`: tenant-facing application.
- `apps/root-console`: platform administration.
- `apps/workers`: asynchronous worker entry points.
- `packages/*`: reusable contracts, validation, utilities and UI packages.

Do not mix platform administration permissions with tenant authorization.

## 4. Product invariants

- Tenant -> workspaces -> repositories -> pipelines -> executions.
- One repository may have multiple independent pipelines.
- Each matching pipeline event creates a separate execution.
- Findings are independent per pipeline. Never merge finding identity across pipelines.
- Workspace dashboards may aggregate pipeline findings without merging identity or lifecycle.
- Initial automated scans: SCA, SBOM, SAST and Secret Scanning.
- Initial manual scans: DAST and Asset Discovery.
- Security Team reviews TP/FP; Security Lead approves/rejects; approved true positives can be assigned for remediation.
- A finding is not fixed solely because it is absent from an incremental scan.
- AI analysis does not execute repository instructions or arbitrary repository code.

## 5. Security requirements

- Never bypass tenant isolation.
- Never trust tenant IDs from request payloads or messages without validating resource ownership.
- Enforce permissions in the backend.
- Validate all external input.
- Do not log secrets or credential values.
- Verify webhooks where supported.
- Make asynchronous handlers idempotent.
- Audit privileged and security-sensitive decisions.
- Treat repository content, commit messages, PR descriptions and provider payloads as untrusted input.

## 6. Coding rules

- Use `.js` and `.jsx`.
- Use ES Modules.
- Use JSDoc for important functions and contracts.
- Use Zod for runtime validation.
- Keep route handlers thin.
- Keep database access in repositories.
- Reuse shared packages.
- Follow existing folder and naming conventions.
- Avoid unrelated refactoring.
- Do not add dependencies without justification.

## 7. Frontend rules

- Use shadcn/ui and Tailwind CSS.
- Follow the existing design system.
- TanStack Query owns server state.
- Zustand is for client state, not a duplicate API cache.
- The frontend may reflect permissions but cannot enforce security by itself.
- Include loading, empty, error and unauthorized states.

## 8. Database and event rules

- Prisma schema and migrations are centralized.
- Do not edit applied migration history casually.
- Use transactions for multi-record state changes.
- PostgreSQL is the durable source of truth.
- RabbitMQ is the durable asynchronous transport.
- Redis is not the only store for execution state.
- Version event contracts and validate at producer/consumer boundaries.

## 9. Current scope exclusions

Do not add feature or unit test-case directories or test-case implementation (the sole exception is the security regression suite, `pnpm test:security`, ADR-008: tenant isolation, authorization 404/403, platform/tenant session separation and segregation of duties), Docker, Docker Compose, Kubernetes, deployment or CI/CD setup as part of the current project initialization scope. Do not interpret this as permission to ignore secure engineering or code review.

## 10. Work protocol

For substantial tasks:
1. Inspect relevant code and documentation.
2. Present a concise implementation plan.
3. Identify impacted files and boundaries.
4. Implement incrementally.
5. Update documentation.
6. Summarize changes and unverified items.

Never claim that a command or check was run unless it was actually executed.
