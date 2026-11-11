# QmentisAI Technology Stack

## Approved stack

| Layer | Technology |
|---|---|
| Language | JavaScript ES Modules |
| Runtime | Node.js LTS |
| Backend | Express 5 (ADR-007) |
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

> **Superseded by ADR-007 (2026-11-11): Express 5 replaces Fastify.** This was an explicit, recorded decision by the product owner. The HTTP contract was frozen in `docs/api/` (`openapi-fastify-baseline.json`, `contract-fastify-baseline.md`) and `pnpm test:security` (ADR-008) was the safety net for the migration. NestJS and other decorator-based frameworks remain excluded.

Previous text, kept for history: *Fastify is the selected backend framework for a pure JavaScript implementation. Do not silently replace it with NestJS or another framework.*

### Backend dependencies added by the Express migration (pinned in `pnpm-workspace.yaml`)

| Package | Version | Why |
|---|---|---|
| `express` | 5.3.0 | The framework (ADR-007); async handler errors are forwarded automatically |
| `helmet` | 8.3.0 | Security response headers (closes an audit gap; decided with the migration) |
| `cors` | 2.8.6 | Credentialed CORS with the exact origin list |
| `cookie-parser` | 1.4.7 | Reads the tenant and platform session cookies |
| `pino-http` | 11.0.0 | Request logging on the existing Pino logger, with the existing redaction and correlation id (pairs with `pino` 10) |
| `express-rate-limit` | 8.7.1 | Global per-IP request limit before authentication (login throttling stays in `auth/login-throttle.js`) |
| `rate-limit-redis` | 6.0.1 | Redis store for the global limit so it is shared across instances (needs `express-rate-limit` 8.6+) |
| `@asteasolutions/zod-to-openapi` | 7.3.4 | OpenAPI 3.0.3 generated from the same Zod schemas that validate requests. v7 is the last line that supports Zod 3 (v8+ need Zod 4, which the workspace does not use) |
| `swagger-ui-express` | 5.0.1 | Interactive docs at `/api/v1/docs`, only when `OPENAPI_ENABLED` (off in production by default). Its transitive `@scarf/scarf` install script (telemetry) is explicitly denied in `allowBuilds` |

Removed at cutover: `fastify`, `fastify-plugin`, `@fastify/cookie`, `@fastify/cors`, `@fastify/swagger`, `zod-to-json-schema`.

New configuration: `TRUST_PROXY` (hop count or addresses; `true` is refused), `RATE_LIMIT_WINDOW_MS` (60000), `RATE_LIMIT_MAX` (600).

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
