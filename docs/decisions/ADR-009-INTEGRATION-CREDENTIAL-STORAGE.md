# ADR-009: Integration credential storage (SecretStore, envelope encryption)

- **Status:** Accepted (2026-11-11, on the product owner's instruction). **Foundation implemented (2026-11-11) as a standalone capability, not tied to integrations**: `SecretStore`, key provider, tables, startup guards, redaction, audit and security-suite checks exist and are off by default (`SECRETS_ENABLED`). The re-encryption job (DEK rotation) is deferred (OPEN_DECISIONS). The integrations module (Phase 5) will use it.
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
| `put({ tenantId, purpose, plaintext, actor })` | Encrypts and stores; returns an opaque `secretRef` (a random UUID, never derived from the value) |
| `resolve({ tenantId, secretRef, purpose })` | Looks the secret up by `secretRef` AND `tenantId` (another tenant's ref behaves exactly like a missing one), decrypts and returns the plaintext **to the calling process only**; `purpose` must match the stored one |
| `rotate({ tenantId, secretRef, plaintext, actor })` | Replaces the value under the same `secretRef`, records the new key version |
| `delete({ tenantId, secretRef, actor })` | Removes the ciphertext (see Deletion) |
| `describe({ tenantId, secretRef })` | Metadata only: purpose, key version, created/rotated timestamps. Never the value or a fragment of it. `toSecretResponse` is the API view (reference, purpose, timestamps; no key versions) |

### 2. Envelope encryption

- **Cipher:** AES-256-GCM for secrets and for wrapping keys; a fresh random 96-bit nonce per encryption; the authentication tag is stored with the ciphertext.
- **Additional authenticated data (AAD):** `tenantId + secretId + purpose + keyVersion` (the DEK version), encoded as a JSON array so field boundaries are unambiguous. A ciphertext copied to another tenant, record, purpose or key version fails authentication. **Nonce:** a fresh random 96-bit value per encryption, stored beside the ciphertext; the 128-bit GCM tag is stored at the end of the ciphertext.
- **Per-tenant data keys (DEK):** each tenant has its own 256-bit data key, generated on first use. DEKs are stored only **wrapped** by the master key, with the master key version; the unwrapped DEK lives in process memory only, for the duration of an operation (no Redis, no disk, no logs).
- **Master key (KEK) behind a `KeyProvider` interface** (`wrap`, `unwrap`, `currentVersion`; wrapping also uses AES-256-GCM with the AAD `"dek" + tenantId + dekVersion + masterKeyVersion`):
  - development: an environment key (`SECRET_MASTER_KEY`, base64, **validated at startup to decode to exactly 32 bytes**, plus `SECRET_MASTER_KEY_VERSION`); the `env` provider is **refused in production**;
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

`tenant_data_keys`: `tenantId`, `version`, `wrappedKey`, `masterKeyVersion`, `status` (active, retiring, retired), `createdAt`. `secrets`: `id` (the `secretRef`), `tenantId`, `purpose`, `ciphertext`, `nonce`, `dekVersion`, `createdAt`, `rotatedAt`, `deletedAt`. Every row carries `tenantId` and is queried with it; `integrationId` links live on the integration record, not in the secret.

## Implementation notes (foundation, 2026-11-11)

- **Where:** `packages/infra/src/secrets` (crypto, `KeyProvider`, `SecretStore`, `toSecretResponse`, `assertSecretFreeMessage`, `resolveFromMessage`), `packages/db/src/secret-repository.js` (Prisma, tenant in every `where`), tables `tenant_data_keys` and `secrets` (migration `20261111200000_secret_storage_foundation`; at most one active data key per tenant is a partial unique index), `apps/api/src/runtime/secrets.js` (wiring and audit), `ctx.secrets` is `null` unless `SECRETS_ENABLED`.
- **Startup guards (`SECRETS_ENABLED=true`):** the master key must be set, base64 and exactly 32 bytes; `SECRET_KEY_PROVIDER` other than `env` is refused ("adapter not implemented yet"); `env` in production is refused ("development only; production needs a KMS or Vault adapter"). Messages name the variable and the problem, never the value. Until a KMS/Vault adapter exists, production cannot enable secrets.
- **Audit:** `secret.created`, `secret.rotated`, `secret.deleted` in the tenant audit log, written in the same transaction as the change (audit failure rolls the change back); metadata = purpose, key versions, actor; never a value.
- **Redaction:** log redaction now covers `plaintext`, `masterKey`, `secretValue`, `dek`, `wrappedKey` and `ciphertext` (top level and one level deep).
- **Write-only and by-reference:** `toSecretResponse` is the only API view; queue messages are checked with `assertSecretFreeMessage` and workers use `resolveFromMessage` (tenant from the message, foreign refs fail like missing ones). No endpoint exists yet; the integrations spec decides the routes and permissions.
- **Security suite:** `SEC-001..009` (cross-tenant ref, wrong purpose, AAD binding to the secret id, ciphertext moved across tenants, no plaintext at rest, API view without value or key versions, audit without value, rotate/delete, message guard). They run in-process against the disposable database because the store has no HTTP surface yet (ADR-008). A deliberate AAD bug was caught by `SEC-003`.
- **Deferred (item 6):** the re-encryption job for DEK rotation. Rotation of a secret's value (`rotate`) works and moves it to the tenant's current DEK version; master-key and DEK rotation campaigns are Open (see OPEN_DECISIONS).

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
| DEK / master-key rotation campaign (the re-encryption job) | Not implemented; deferred on purpose | Build it with the first production KeyProvider; until then rotation is per secret (`rotate`) |
| Crypto-shredding when a tenant becomes terminally deactivated (see AUTHORIZATION Q25) | Destroy the tenant DEK at terminal deactivation; keep until a purge job | Destroy the DEK when the retention window ends |
| ~~Environment variable name and format of the development master key~~ | Decided with the implementation: `SECRET_MASTER_KEY` (base64, 32 bytes) and `SECRET_MASTER_KEY_VERSION` | Resolved |
