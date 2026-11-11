# QmentisAI Technology Stack

## Approved stack

| Layer | Technology |
|---|---|
| Language | JavaScript ES Modules |
| Runtime | Node.js LTS |
| Backend | Express 5 (ADR-007: accepted, migration pending; `apps/api` currently runs Fastify 5) |
| Frontend | React + Vite |
| UI | shadcn/ui |
| CSS | Tailwind CSS |
| Icons | Lucide React |
| Monorepo | pnpm workspaces + Turborepo |
| Database | PostgreSQL |
| ORM | Prisma |
| Cache | Redis |
| Messaging | RabbitMQ |
| Real-time | Socket.IO |
| API docs | OpenAPI |
| Routing | React Router |
| Server state | TanStack Query |
| Client state | Zustand |
| Forms | React Hook Form |
| Validation | Zod |
| Tables | TanStack Table |
| Charts | Recharts |
| Notifications | Sonner |
| Logging | Pino |
| Date utilities | date-fns |
| Lint/format | ESLint + Prettier |
| Security regression suite | `node:test` through `pnpm test:security` (ADR-008; no extra dependency) |

## Language rules

- JavaScript only; do not introduce TypeScript without an approved ADR.
- Use ES Modules.
- `.js` for backend, workers and shared logic.
- `.jsx` for React components.
- Use JSDoc for important contracts and public functions.
- Use Zod for runtime validation.

## Backend framework note

> **Superseded by ADR-007 (2026-11-11): Express 5 replaces Fastify.** This was an explicit, recorded decision by the product owner, not a silent replacement. The migration has **not** started: `apps/api` runs Fastify 5 until cutover, the HTTP contract is frozen in `docs/api/` (`openapi-fastify-baseline.json`, `contract-fastify-baseline.md`), and `pnpm test:security` (ADR-008) is its safety net. NestJS and other decorator-based frameworks remain excluded.

Previous text, kept for history: *Fastify is the selected backend framework for a pure JavaScript implementation. Do not silently replace it with NestJS or another framework.*

**Dependencies expected from the migration (candidates; none added yet).** Each must be pinned and justified here when added: `express` (the framework), `cookie-parser` (session cookies), `cors` (credentialed CORS with the exact origin list), `pino-http` (request logging with the existing redaction and correlation id), and optionally `helmet` (security headers). OpenAPI generation is an open decision in ADR-007 (hand-written over the route registry, or a library). `fastify`, `fastify-plugin`, `@fastify/cookie`, `@fastify/cors` and `@fastify/swagger` are removed at cutover.

## Data and messaging responsibilities

- PostgreSQL: durable business state.
- RabbitMQ: durable asynchronous job transport.
- Redis: cache, locks, rate limiting and temporary coordination.
- Socket.IO: authorized real-time notifications, not durable state.

## Versioning

Use compatible, pinned dependency versions and commit the lockfile. Do not use floating versions in production dependency manifests.

### Frontend dependencies (tenant-web foundation, 2026-11-11; versions pinned in `pnpm-workspace.yaml`)

All are from the approved stack except where noted. `lucide-react` is pinned to an older release because the newest one was published the same day and the workspace release-age safeguard is kept (no `minimumReleaseAgeExclude`).

| Package | Why |
|---|---|
| `tailwindcss`, `@tailwindcss/vite` | Tailwind v4, CSS-first (DESIGN_SYSTEM §3.1) |
| `react-router` | Routing (v8 declarative API) |
| `@tanstack/react-query` | Server state |
| `zustand` | UI preferences and workspace selection only |
| `react-hook-form`, `@hookform/resolvers`, `zod` | Forms with Zod validation (zod stays on the workspace catalog version) |
| `lucide-react`, `sonner` | Icons and toasts |
| `@radix-ui/react-dropdown-menu`, `-tooltip`, `-slot`, `-label`, `-dialog`, `-tabs` | Accessible primitives behind the shadcn/ui-style components |
| `class-variance-authority`, `clsx`, `tailwind-merge` | Variant and class-name utilities used by shadcn/ui components |
| `@fontsource-variable/geist`, `@fontsource-variable/geist-mono` | Self-hosted approved fonts |

Not yet installed (in the approved stack, no screen needs them yet): TanStack Table, Recharts.
