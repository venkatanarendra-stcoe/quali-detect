# QmentisAI API Standards

## Route convention

Use versioned REST endpoints under `/api/v1`.

Tenant examples:
- `/api/v1/workspaces`
- `/api/v1/repositories`
- `/api/v1/pipelines`
- `/api/v1/executions`
- `/api/v1/scans`
- `/api/v1/findings`
- `/api/v1/security-reviews`
- `/api/v1/approvals`
- `/api/v1/remediation`
- `/api/v1/integrations`
- `/api/v1/policies`

Platform examples:
- `/api/v1/platform/tenants`
- `/api/v1/platform/plans`
- `/api/v1/platform/subscriptions`
- `/api/v1/platform/licenses`
- `/api/v1/platform/entitlements`
- `/api/v1/platform/usage`

## Request rules

- Validate params, query and body with Zod.
- Authenticate before protected operations.
- Establish trusted tenant context.
- Authorize the action and resource.
- Check entitlement/quota for metered operations.
- Apply pagination to collection endpoints.
- Define filtering and sorting explicitly.
- Use idempotency keys for operations where duplicate submission could cause side effects.

## Response convention

Success example:

```json
{
  "success": true,
  "data": {
    "id": "resource-id"
  },
  "meta": {
    "correlationId": "correlation-id"
  }
}
```

Error example:

```json
{
  "success": false,
  "error": {
    "code": "RESOURCE_NOT_FOUND",
    "message": "The requested resource was not found."
  },
  "meta": {
    "correlationId": "correlation-id"
  }
}
```

## Error rules

Use stable machine-readable error codes. Do not expose stack traces, SQL details, provider secrets or internal implementation details.

## Documentation

Maintain OpenAPI documentation alongside route schemas. Document authentication, permissions, request validation, response structures and error cases.

## Cursor pagination (2026-11-13, owner decision)

Offset pagination (`page`, `pageSize`, `totalItems`, `totalPages`) stays the default and unchanged. Collections that serve a "Load more" list also accept cursor (keyset) pagination, added as a backward-compatible extension. Today: `GET /repositories`, `GET /pipelines`, `GET /repositories/{repositoryId}/pipelines` and `GET /audit-logs` (tenant), and, with the same contract and a platform scope, `GET /platform/tenants` and `GET /platform/audit-logs` (Root Console; added 2026-11-13, owner decision). The other Root Console collection, `GET /platform/plans`, is a small unpaginated catalogue and stays as it is; there are no other platform lists yet (platform users, support sessions, feature flags do not exist), and a future list opts in the same way. A collection opts in with `createCollectionQuerySchema({ cursor: true })`; its repository then uses `findKeysetPage` and its service `cursorContext` (`apps/api/src/lib/keyset.js`).

- **Request:** `cursor` (opaque string, at most 1024 characters) and `limit` (1 to the collection's maximum page size; acts as `pageSize`). `page` cannot be combined with `cursor` (`400 VALIDATION_FAILED`). Filters and `sort` are the endpoint's own and must be repeated unchanged on every page.
- **Response:** `meta.pagination` keeps `page`, `pageSize`, `totalItems`, `totalPages` (totals describe the whole filtered result, not the remainder) and adds `nextCursor` (string, or `null` on the last page) and `hasMore`. Every response of these endpoints carries both, offset requests included, so a client can start a cursor walk from its first page. A cursor request reports `page: 1`.
- **Order:** every supported sort is made total by appending the row `id` as the last sort term (ascending; descending for the audit log, as before), so pages never overlap or skip rows, also when rows are inserted between requests. NULL sort keys follow PostgreSQL (last ascending, first descending) and the keyset predicate mirrors it. `lastRequestedAt` (an aggregate, ordered in memory over at most 5000 pipelines) uses latest request, then name, then id.
- **The cursor is a position, never a scope, and it is signed.** The token is base64url of `[format 1 byte][key id 1 byte][HMAC-SHA256 32 bytes][JSON sort key of the last row]`. The MAC is keyed with a purpose-specific subkey (HKDF-SHA256 over the fixed label `qmentis:cursor:v1` of the server secret `CURSOR_SIGNING_SECRET`; the raw secret never signs) and covers the format, the key id, the payload and a binding hash of endpoint, **scope**, sort, filters and parent. The binding is recomputed from the request, never read from the token. Scope is `tenant:<tenantId>` on tenant lists and `platform:<platformUserId>` on Root Console lists (the authenticated principal, never request input), so a tenant cursor never fits a platform list, a platform cursor never fits a tenant list, and one platform user's cursor never fits another's. Tenant, workspace visibility and permissions are re-applied from the session on every request, never read from the cursor, so even a valid cursor only chooses where in the caller's own scoped result the page starts. A cursor that does not parse, fails the MAC (tampered, forged, signed with another or a retired key, an unkeyed checksum, the old unkeyed layout), has a wrong key type, or was minted for another endpoint, scope, sort, filter set or parent answers `400 INVALID_CURSOR` (`ERROR_CODES.INVALID_CURSOR`, constant-time comparison, no detail on why). A tenant session on a platform list still gets the unchanged `404` before any cursor is looked at, and a platform session on a tenant list the unchanged `401`.
- **Signing key and rotation.** `CURSOR_SIGNING_SECRET` (apps/api config, Zod) is a comma-separated list of 1 to 4 secrets of 32 to 256 characters, newest first: the first signs, all verify. The key id byte is a fingerprint of the derived subkey (first byte of its SHA-256), so a verifier picks the key without positional meaning. Rotation: put the new secret first, keep the old one for as long as cursors signed with it may still be in use (cursors are short-lived "Load more" positions), then remove it; a cursor signed with an unlisted key is refused like any forged one and the client restarts its walk. Required in production; in development and test an unset value generates a random per-process secret (cursors then stop working when the API restarts, same effect as a removed key). Same handling as the other secrets: validated at startup, never logged or returned (`describeConfig` only says `configured` or `ephemeral`), placeholder in `apps/api/.env.example`, value only in the environment. All API instances must share the value.
- **Platform lists (Root Console).** `GET /platform/tenants`: `status`, `plan`, `q`, `sort` (`name`, `slug`, `status`, `createdAt`; default `name:asc`; `status` sorts in the enum's declaration order active, trial, suspended, deactivated), ties by `id` ascending. `GET /platform/audit-logs`: `actor`, `action`, `tenantId`, `from`, `to`, `result`, `sort` (`createdAt`, `action`; default `createdAt:desc`), ties by `id` descending. Both keep `page`/`pageSize` and add `cursor`, `limit` (1 to 100), `meta.pagination.nextCursor` and `hasMore` exactly as above. Platform permissions are unchanged (`platform.tenant.view`, `platform.audit_log.view`).
- **Precision:** keyset comparison uses JavaScript `Date` values (milliseconds); timestamps are written by Prisma, which has that precision.
- **Indexes:** keyset predicates keep the tenant (and workspace) prefix of existing indexes; no index was added. The audit log has `(tenant_id, created_at)`; pipelines `(tenant_id, workspace_id, deleted_at, name)`; repositories are bounded per tenant by the repository quota.
- Security suite: `PAG-001..025` (ADR-008): `PAG-016` and `PAG-017` cover the keyed MAC and rotation, `PAG-018..025` the platform lists.

## Contract baseline and transport independence

The API contract is independent of the HTTP framework (ADR-007). The Fastify-era contract is frozen in `docs/api/` as the reference; `pnpm contract:snapshot` writes the Express twins (`openapi-express.json`, `contract-express.*`) and `pnpm contract:parity` diffs them (`parity-report.md`):

- `openapi-fastify-baseline.json`: the OpenAPI document exactly as served.
- `contract-fastify-baseline.json` and `.md`: one record per operation (method, path, audience, permission and its scope, success status, documented error statuses, **transport** error codes (exact) and **domain** error codes (a per-module superset), response envelope and `data` shape).
- Regenerate with `pnpm contract:snapshot`; the script fails if an OpenAPI operation cannot be matched to a route source. A contract change is reviewed as a diff of these files.

Rules the Express migration must preserve:

- Same paths under `/api/v1` (platform under `/api/v1/platform`), statuses, envelopes, cookie names/paths/flags and stable error codes.
- **Authentication precedes validation (ADR-007, changed from the Fastify era):** an unauthenticated caller gets `401` regardless of input, and an unusable tenant `403`, before input is validated; invalid input then answers `400 VALIDATION_FAILED` before authorization (`403`/`404`) is decided. Public routes (login) validate first. Changing this order needs an ADR.
- A route without a declared audience must refuse to register; platform routes only under `/api/v1/platform/`.
- A workspace the caller cannot see answers `404` with a body identical to a missing one; a visible resource without permission answers `403` (see `docs/AUTHORIZATION.md` §5.9). `pnpm test:security` (ADR-008) enforces this.

Known gap against the request rules above: `Idempotency-Key` is not implemented yet (duplicates rely on unique constraints and return `409`).

## HTTP edge (Express 5, 2026-11-11)

- **Headers and CORS:** `helmet` on every response. CORS only for the configured origins (`CORS_ALLOWED_ORIGINS`: the tenant-web and Root Console origins, exact `scheme://host[:port]`, no wildcard, validated at startup); credentials are allowed only for those origins. A request from another origin gets no CORS headers, and an unsafe request carrying an unknown `Origin` is refused with `403` (CSRF check).
- **Proxy and bodies:** `TRUST_PROXY` (default off; a hop count or addresses, never `true`). `REQUEST_BODY_LIMIT_BYTES` (413). A request body must be `application/json`; anything else is `415 UNSUPPORTED_MEDIA_TYPE`.
- **Rate limits (Redis-backed, `RATE_LIMIT_*`):** a global per-IP limit, plus per-route profiles with their own counter per route: `auth` (public sign-in endpoints, per IP, strict), `write` (authenticated create/side-effect endpoints, per tenant + user), `webhook` (per IP, ready for provider webhooks). A refusal is `429 RATE_LIMITED` with `RateLimit` and `Retry-After` headers. Sign-in endpoints also have the progressive per-account throttle (ADR-010).
- **Idempotency-Key:** optional header on POST endpoints that create resources or trigger side effects. Keys are scoped by tenant + user + route and stored in Redis for `IDEMPOTENCY_TTL_SECONDS` (default 24 h). Same key and same request: the stored 2xx response is replayed (`Idempotent-Replayed: true`). Same key with a different request, or while the first is still running: `409 IDEMPOTENCY_CONFLICT` (`details.reason`: `different_request` or `in_progress`). Failed requests are not stored.
