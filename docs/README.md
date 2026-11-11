# QmentisAI Documentation Pack

This directory is the shared documentation source of truth for QmentisAI development with Cursor, Claude Code, Codex and Kiro.

## How to use

1. Keep this entire `docs/` directory in the QmentisAI repository.
2. Read `ai-development/AI_DEVELOPMENT_WORKFLOW.md` before starting implementation.
3. Give coding agents `ai-development/AGENT_INSTRUCTIONS.md` as the common instruction source.
4. Read product, architecture, technical and security documents before changing foundational code.
5. Implement one module at a time using the module specification template.
6. Update documentation whenever implementation changes approved behavior.

## Document status

- **Confirmed** means explicitly agreed in the product/architecture discussions.
- **Recommended** means a proposed engineering choice to validate during implementation.
- **Open** means business or technical input is still needed.

Do not treat recommendations or open items as confirmed requirements.

## Important current project constraints

- JavaScript (ES Modules), not TypeScript.
- Backend: Node.js + Express 5 (ADR-007, implemented).
- Frontend: React + Vite + shadcn/ui + Tailwind CSS.
- Database: PostgreSQL + Prisma.
- Redis for cache/coordination; RabbitMQ for durable asynchronous messaging.
- Socket.IO for authorized real-time updates.
- pnpm workspaces + Turborepo monorepo.
- Two separate frontends: Tenant Application and Root Console.
- Backend starts as a modular monolith with separate worker entry points.
- Do not add test-case structures, Docker, Docker Compose or deployment setup to the current initialization scope.
- Do not silently change approved architecture or product decisions.
