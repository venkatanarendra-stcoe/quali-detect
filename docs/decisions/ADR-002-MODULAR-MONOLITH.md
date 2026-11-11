# ADR-002: Start with a Modular Monolith and Separate Workers

- **Status:** Accepted
- **Decision:** Implement backend domains in one modular Fastify application, with separate worker entry points for asynchronous workloads.

## Context

QmentisAI has multiple business domains, but premature microservice separation would add operational and integration complexity.

## Decision

Use explicit domain boundaries inside a modular monolith. Run long-running work in independent worker processes. Extract services later only when scaling, ownership or isolation requirements justify it.

## Consequences

- Shared deployment unit for API domains initially.
- Independent worker lifecycle.
- Domain boundaries must be enforced in code.
- Avoid cross-module database shortcuts.
