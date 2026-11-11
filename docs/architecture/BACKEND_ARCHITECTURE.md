# QmentisAI Backend Architecture

## Stack

- Node.js LTS.
- JavaScript ES Modules.
- Fastify.
- Prisma.
- PostgreSQL.
- Redis.
- RabbitMQ.
- Socket.IO.
- OpenAPI.

## Architectural style

Use a modular monolith organized by business domain. Each module owns its routes/controllers, services, repositories, validation, policies and events.

## Module internal convention

```text
module-name/
  routes/
  controllers/
  services/
  repositories/
  schemas/
  policies/
  events/
  listeners/
  mappers/
  constants/
  index.js
```

Fastify plugins should register module routes and dependencies. Avoid hidden global mutable state.

## Domain boundaries

- platform
- identity
- organization
- engineering
- integrations
- analysis
- scanning
- findings
- security-workflow
- governance
- communication
- reporting

## Request lifecycle

1. Parse request.
2. Validate input.
3. Authenticate caller.
4. Establish tenant and resource context.
5. Authorize action.
6. Check tenant status and entitlement where relevant.
7. Execute domain service.
8. Persist state.
9. Emit durable domain event when required.
10. Return standardized response.

The exact order of authentication, tenant resolution and authorization must be implemented carefully so unauthenticated input cannot select arbitrary tenant context.

## Error handling

Use stable error codes and a centralized Fastify error handler. Do not return stack traces, secrets, raw SQL errors or internal provider credentials.

## Database access

Keep Prisma access behind repository modules. Use transactions for multi-record state transitions. Add explicit tenant filters to tenant-owned queries and consider database-level defense-in-depth where feasible.

## JavaScript conventions

- ES Modules.
- JSDoc on public service functions and complex objects.
- Zod at external boundaries.
- `const` by default.
- No TypeScript syntax.
- No CommonJS unless a third-party compatibility requirement is documented.
