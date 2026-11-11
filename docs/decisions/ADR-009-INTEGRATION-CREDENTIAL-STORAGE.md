# ADR-009: Integration credential storage (SecretStore, envelope encryption)

- **Status:** Accepted (2026-11-11, on the product owner's instruction). **Not implemented yet**: no integration tables exist; implementation belongs to the integrations module (Phase 5). The code changes this requires are listed in the work item that introduced this ADR and in `docs/modules/integrations/` when that spec is written.
- **Date:** 2026-11-11
- **Decision owners:** Product owner (decision); Claude Code (documentation)
- **Related:** `docs/technical/SECURITY_GUIDELINES.md` (Secrets and credentials), `docs/architecture/INTEGRATION_ARCHITECTURE.md`, `docs/architecture/TENANT_ISOLATION.md`, ADR-003

## Context

Integrations (source providers, issue trackers, chat, AI coding tools, Vault-compatible systems) need tokens, keys and client secrets. The guidelines require them encrypted at rest, decryptable only by services that need them, never logged, revocable and rotatable. Workers are separate processes that receive jobs through RabbitMQ; a message must never become a place where a secret is stored or leaked.

## Decision

### 1. One interface: `SecretStore`

All credential access goes through a `SecretStore` (JSDoc contract in `packages/infra`, server-only). No module reads or writes credential ciphertext directly.

| Operation | Behavior |
|---|---|
| `put({ tenantId, kind, plaintext, actor })` | Encrypts and stores; returns an opaque `secretRef` (never derived from the value) |
| `resolve({ tenantId, secretRef, purpose })` | Verifies the secret belongs to `tenantId`, decrypts and returns the plaintext **to the calling process only** |
| `rotate({ tenantId, secretRef, plaintext, actor })` | Replaces the value under the same `secretRef`, records the new key version |
| `delete({ tenantId, secretRef, actor })` | Removes the ciphertext (see Deletion) |
| `describe({ tenantId, secretRef })` | Metadata only: kind, key versions, created/rotated/deleted timestamps. Never the value or a fragment of it |

### 2. Envelope encryption

- **Cipher:** AES-256-GCM for secrets and for wrapping keys; a fresh random 96-bit nonce per encryption; the authentication tag is stored with the ciphertext.
- **Additional authenticated data:** `tenantId | secretId | kind | dekVersion`, so a ciphertext copied to another tenant or record fails to decrypt.
- **Per-tenant data keys (DEK):** each tenant has its own 256-bit data key, generated on first use. DEKs are stored only **wrapped** by the master key, with the master key version; the unwrapped DEK lives in process memory only, for the duration of an operation (no Redis, no disk, no logs).
- **Master key (KEK) behind a `KeyProvider` interface** (`wrap`, `unwrap`, `currentVersion`):
  - development: an environment key (a base64 32-byte value from the environment; it is refused in production);
  - later: a KMS or Vault adapter (the first adapter is Open). The interface is fixed now so the switch changes configuration, not callers.
- **Key versions are stored** with every record (master key version on the wrapped DEK, DEK version on each secret) so rotation is possible without guessing which key encrypted what.
- **Rotation:** master key rotation re-wraps tenant DEKs (cheap, no secret is re-encrypted); DEK rotation creates a new DEK version and re-encrypts that tenant's secrets (lazily on `resolve` and by a background job); old versions are kept only until nothing references them. Rotating a credential's value is `rotate`.

### 3. Plaintext handling

- Never logged: redaction paths cover credential fields, and the SecretStore never passes plaintext to a logger or an error message.
- Never returned by any API: credential fields are **write-only**; responses show metadata (`secretRef`, kind, last rotated, key version is not exposed), never the value or a masked part of it.
- Never in queue messages, events, outbox rows, audit payloads, cache entries or exports. Messages carry `{ tenantId, integrationId, secretRef }`.
- **Workers fetch by reference with a tenant check:** a worker calls `resolve({ tenantId, secretRef })` using the `tenantId` of the message and revalidates that the integration and the secret belong to that tenant (TENANT_ISOLATION worker rules). A mismatch is a non-retryable failure, logged without the value.
- Plaintext exists only in the memory of the process that needs it, for the shortest time (no caching of decrypted values). Only API and worker processes that perform provider calls are configured with key access.

### 4. Audit

Create, rotate and delete are audited with the standard immutable audit service: actor, tenant, `secretRef`, kind, key versions, timestamp, result. The audit payload never contains the value. Whether successful `resolve` calls are audited is Open (see below).

### 5. Deletion

`delete` removes the ciphertext and marks the record deleted; deleted references fail `resolve` immediately. Provider-side revocation is the integration module's responsibility and is requested separately (Disconnect and credential revocation, INTEGRATION_ARCHITECTURE).

## Logical data model (not a Prisma schema)

`tenant_data_keys`: `tenantId`, `version`, `wrappedKey`, `masterKeyVersion`, `status` (active, retiring, retired), `createdAt`. `secrets`: `id` (the `secretRef`), `tenantId`, `kind`, `ciphertext`, `nonce`, `dekVersion`, `createdAt`, `rotatedAt`, `deletedAt`. Every row carries `tenantId` and is queried with it; `integrationId` links live on the integration record, not in the secret.

## Alternatives considered

1. **Database-level encryption (pgcrypto) with one application key:** one key for every tenant, no per-tenant blast-radius limit, keys travel in SQL. Rejected.
2. **Store credentials only in Vault/KMS:** strongest, but a hard external dependency from day one and not available in development. Kept as a later adapter behind the same interface.
3. **Send credentials to workers inside job messages:** simplest, but puts secrets in RabbitMQ, retries, dead-letter queues and logs. Rejected.

## Consequences

### Positive
- A tenant's key compromise or deletion is contained to that tenant; a stolen database dump alone does not expose credentials.
- Rotation is possible at three levels (value, tenant key, master key) because versions are recorded.
- Messages and logs stay free of secrets by construction.

### Negative / trade-offs
- More moving parts (key provider, key versions, a re-encryption job).
- In development the master key is an environment value, so a developer machine's protection is only as good as its environment.
- Every provider call needs a decrypt; no plaintext caching means a small latency cost per call.

## Security and operational impact

New server-only code in `packages/infra`, new tables, a new environment variable for the development master key, redaction additions and audit actions. No change to existing endpoints. The development key must never be committed; production without a KMS/Vault adapter must refuse to start the integrations module.

## Open (do not guess)

| Topic | Options | Recommendation |
|---|---|---|
| First production `KeyProvider` | AWS KMS, Google Cloud KMS, HashiCorp Vault transit | Decide with the deployment target (out of scope now) |
| Audit of successful `resolve` calls | Audit each; metrics/log only; sampled | Metric and structured log without the value; audit only failures and denials |
| DEK rotation schedule | Manual; periodic; on incident only | Manual plus on incident until operations are defined |
| Crypto-shredding when a tenant becomes terminally deactivated (see AUTHORIZATION Q25) | Destroy the tenant DEK at terminal deactivation; keep until a purge job | Destroy the DEK when the retention window ends |
| Environment variable name and format of the development master key | | `SECRET_MASTER_KEY` (base64, 32 bytes), plus a version number |
