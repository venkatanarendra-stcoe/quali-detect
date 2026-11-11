# QmentisAI Backend Architecture

## Stack

- Node.js LTS.
- JavaScript ES Modules.
- Express 5 (ADR-007: accepted, migration pending; the code currently runs Fastify 5).
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

The module convention and the layering are **framework-independent**. After the migration to Express 5:

- `routes/` hold Express routers, registered only through one helper (`defineRoute({ audience, permission, schema, handler })`) that **requires** `audience` and throws at startup otherwise (the guarantee Fastify's `onRoute` hook gives today).
- `controllers/` take `(req, res)` instead of `(request, reply)`; `res.success` / `res.paginated` produce the same envelopes.
- Fastify plugins become **middleware and app factories**: `createApp({ config, modules })` builds the app; each module exports a factory returning a `Router`, mounted at its prefix; there is no plugin encapsulation, so dependencies are passed explicitly.
- Services, repositories, policies, mappers, Zod schemas, the authorization engine and the Prisma/infra packages do not change.

Until the migration lands, the code is Fastify: modules are `fastify-plugin` plugins registered by `plugins/modules.js`. The HTTP contract that both must satisfy is in `docs/api/`; `pnpm test:security` must pass on both.

**Fixed middleware order** (a wrong order can bypass security; it reproduces current behavior, including that input validation errors are produced before authentication):
correlation id, request logging, body parsing with limit, CORS, cookies, CSRF/Origin check on unsafe methods, input validation, authentication by route audience (`public`, `user`, `tenant`, `platform`), tenant context from the session only, `authorize(permission, scope)` (404 when not visible, 403 when not permitted), handler, envelope and error handler.

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

Use stable error codes and a centralized error handler (Express error-handling middleware after ADR-007; a Fastify error handler until then). Do not return stack traces, secrets, raw SQL errors or internal provider credentials.

## Database access

Keep Prisma access behind repository modules. Use transactions for multi-record state transitions. Add explicit tenant filters to tenant-owned queries and consider database-level defense-in-depth where feasible.

## JavaScript conventions

- ES Modules.
- JSDoc on public service functions and complex objects.
- Zod at external boundaries.
- `const` by default.
- No TypeScript syntax.
- No CommonJS unless a third-party compatibility requirement is documented.
