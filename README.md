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

Node.js >= 22.22 (LTS, see `.nvmrc`; react-router 8 needs it) and pnpm 12 (`corepack enable`).

## Commands

```bash
pnpm install
pnpm lint          # turbo: lint every package
pnpm build         # turbo: build packages that define a build script
pnpm dev           # turbo: starts the API, tenant-web, root-console AND the workers (pipeline, scan, scm, outbox, scheduler), each with watch/restart
pnpm format        # prettier
```

Copy each app's `.env.example` to `.env` for local configuration. Never commit `.env` files.

`pnpm dev` runs every package's `dev` script through turbo. `apps/workers` has a small launcher (`apps/workers/scripts/dev.js`, no extra dependency) that runs the five workers of the local stack, `pipeline`, `scan`, `scm`, `outbox` and `scheduler`, under `node --watch` with prefixed output. `analysis`, `notification` and `usage` are not in the default set: run `pnpm --filter @qmentisai/workers dev:<name>`, or pick the set with `WORKERS=pipeline,scan pnpm dev`. The workers need RabbitMQ and the same `DATABASE_URL` as the API (see `apps/workers/.env.example`); the execution orchestrator stays off until `EXECUTION_ORCHESTRATOR_ENABLED=true`.
