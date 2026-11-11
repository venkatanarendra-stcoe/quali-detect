# ADR-003: Enforce Tenant Isolation Across All Layers

- **Status:** Accepted
- **Decision:** Tenant ownership and authorization must be enforced in APIs, data access, workers, caches, events, storage, search and exports.

## Context

QmentisAI is a multi-tenant security platform. Cross-tenant data exposure is a critical risk.

## Decision

Every tenant-owned operation must establish trusted tenant context and validate resource ownership. Root Console uses separate platform permissions. Background jobs must revalidate tenant and resource state.

## Consequences

- Tenant context is a first-class application concern.
- Tenant IDs must be included in relevant records and job envelopes.
- Audit and security review are required for support access.
