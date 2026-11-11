# QmentisAI

AI-native security engineering workflow platform. Hierarchy: Tenant -> Workspace -> Repository -> Pipeline -> Execution -> Findings.

Documentation lives in [`docs/`](docs/README.md) (source of truth). Agent rules: `CLAUDE.md`, `AGENTS.md`.

## Layout

| Path                 | Package                   | Purpose                                                                                                     |
| -------------------- | ------------------------- | ----------------------------------------------------------------------------------------------------------- |
| `apps/api`           | `@qmentisai/api`          | API (modular monolith; Express 5 per ADR-007, Fastify until migrated)                                       |
| `apps/workers`       | `@qmentisai/workers`      | Separate worker entry points: pipeline, analysis, scan, notification, usage, scheduler                      |
| `apps/tenant-web`    | `@qmentisai/tenant-web`   | Tenant Application (React + Vite)                                                                           |
| `apps/root-console`  | `@qmentisai/root-console` | Platform administration (React + Vite)                                                                      |
| `packages/shared`    | `@qmentisai/shared`       | Permission keys, navigation definitions, constants                                                          |
| `packages/contracts` | `@qmentisai/contracts`    | Zod schemas, event envelope, error codes                                                                    |
| `packages/db`        | `@qmentisai/db`           | Prisma schema, client singleton, transaction helper, tenant-scoped base repository                          |
| `packages/infra`     | `@qmentisai/infra`        | Server-only Redis (cache, locks, rate limits) and RabbitMQ (publisher, consumer, retries, DLQ) abstractions |
| `packages/ui`        | `@qmentisai/ui`           | Design tokens and generic components                                                                        |
| `packages/config`    | `@qmentisai/config`       | Shared ESLint flat config and Prettier config                                                               |

Phase 1 (repository foundation) contains skeletons only: no business logic.

## Requirements

Node.js >= 22.12 (LTS, see `.nvmrc`) and pnpm 12 (`corepack enable`).

## Commands

```bash
pnpm install
pnpm lint          # turbo: lint every package
pnpm build         # turbo: build packages that define a build script
pnpm dev           # turbo: dev scripts (skeletons print a notice)
pnpm format        # prettier
```

Copy each app's `.env.example` to `.env` for local configuration. Never commit `.env` files.
