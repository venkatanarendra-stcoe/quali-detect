# QmentisAI Backend Architecture

## Stack

- Node.js LTS.
- JavaScript ES Modules.
- Express 5 (ADR-007, implemented).
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

Avoid hidden global mutable state: dependencies are built from configuration and passed explicitly.

### Transport (ADR-007)

The module convention and the layering are **framework-independent**. `apps/api` runs on Express 5:

- `routes/` declare routes through the route kit (`src/lib/route-kit.js`): `r.get(path, { config: { audience }, preHandler, schema }, handler)`. The kit **requires** `audience`, enforces the platform-path placement rules and throws at startup otherwise, and is the only code that builds a route's middleware chain. Tenant routes live on a router mounted at `/api/v1`, platform routes on a separate router at `/api/v1/platform`, each with its own authentication middleware. The same `schema` Zod objects validate requests and generate OpenAPI (`@asteasolutions/zod-to-openapi`).
- `controllers/` receive Express `(req, res)`; the envelope middleware adds `res.success`, `res.paginated`, `res.code(n)` and `req.id`, `req.principal`, `req.authz` are set by the chain.
- Fastify plugins became **middleware (`src/middleware/`) and factories (`src/runtime/`)**: `createApp({ config, modules })` builds the app; a module's `plugin(ctx)` builds repository -> service -> controller from the shared context and calls `ctx.register(routes, { prefix })`. There is no plugin encapsulation, so dependencies are passed explicitly.
- Services, repositories, policies, mappers, Zod schemas, the authorization engine and the Prisma/infra packages do not change.

The HTTP contract is in `docs/api/` (Fastify baseline kept as reference; `pnpm contract:snapshot` and `pnpm contract:parity` compare the Express app with it); `pnpm test:security` must pass.

**Fixed middleware order** (a wrong order can bypass security; `pnpm test:security` guards it):
correlation id, request logging (pino-http, redaction), security headers (helmet), CORS, global rate limit, cookies, envelope helpers, body parsing with limit (413) and content-type guard (415), CSRF/Origin check on unsafe methods; then, per route, authentication by audience (`public`, `user`, `tenant`, `platform`), tenant context from the session only, input validation (Zod), `authorize(permission, scope)` (404 when not visible, 403 when not permitted), handler; then the JSON 404 and the centralized error handler.

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

Use stable error codes and a centralized error handler (Express error-handling middleware). Do not return stack traces, secrets, raw SQL errors or internal provider credentials.

## Database access

Keep Prisma access behind repository modules. Use transactions for multi-record state transitions. Add explicit tenant filters to tenant-owned queries and consider database-level defense-in-depth where feasible.

## JavaScript conventions

- ES Modules.
- JSDoc on public service functions and complex objects.
- Zod at external boundaries.
- `const` by default.
- No TypeScript syntax.
- No CommonJS unless a third-party compatibility requirement is documented.
