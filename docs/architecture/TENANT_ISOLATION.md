# QmentisAI Tenant Isolation

## Principle

Tenant isolation is a mandatory security boundary, not a UI feature.

## Required enforcement points

- API authentication and authorization.
- Database reads and writes.
- Repository and pipeline lookup.
- Background messages and worker handlers.
- Cache keys and distributed locks.
- Search indexes and analytics.
- Object storage paths and signed URLs.
- Socket.IO rooms and event subscriptions.
- Reports, exports and downloads.
- Integration credentials and webhook routing.

## Data ownership

Every tenant-owned entity must have an explicit tenant ownership path. Where practical, store `tenantId` directly on frequently accessed tenant-owned records and validate consistency with parent resources.

## Query rules

- Never query a tenant-owned record by ID alone.
- Include authenticated tenant scope.
- Validate workspace/repository/pipeline parent-child relationships.
- Avoid accepting tenant ID from request body as authority.
- Treat background job tenant IDs as untrusted until resource ownership is checked.

## Cache and event rules

Include tenant and resource scope in cache keys and event routing. Do not publish sensitive payloads to broad rooms.

## Platform access

Root Console access uses separate platform permissions. Support diagnostics must be explicitly authorized, scoped, logged and auditable.

## Audit

Record privileged cross-tenant support access, tenant lifecycle changes, permission changes and sensitive exports.
