import { createSecretRepository } from "@qmentisai/db";
import { createEnvKeyProvider, createSecretStore, parseMasterKey } from "@qmentisai/infra";

/**
 * Builds the SecretStore (ADR-009) when `SECRETS_ENABLED`, otherwise returns null. Configuration already validated the key
 * (32 bytes) and refused providers that are unsafe or not implemented, so a mistake stops the process at startup.
 * Create, rotate and delete are written to the tenant audit log in the same transaction as the change; entries carry the
 * reference, purpose and key versions, never a value.
 * @param {{ config: any, infra: { db: any }, audit: ReturnType<typeof import("../audit/audit-service.js").createAuditService> }} deps
 */
export function createSecrets({ config, infra, audit }) {
  if (!config.secrets.enabled) return null;
  return createSecretStore({
    repository: createSecretRepository({ db: infra.db }),
    keyProvider: createEnvKeyProvider({
      masterKey: parseMasterKey(config.secrets.masterKey),
      version: config.secrets.masterKeyVersion,
    }),
    audit: (event, { tx }) =>
      audit.tenant.record(
        {
          tenantId: event.tenantId,
          actorUserId: event.actor?.userId,
          action: event.action,
          targetType: "secret",
          targetId: event.secretRef,
          metadata: {
            purpose: event.purpose,
            keyVersions: event.keyVersions,
            ...(event.actor?.platformUserId ? { platformUserId: event.actor.platformUserId } : {}),
            ...(event.actor?.system ? { system: event.actor.system } : {}),
          },
        },
        { tx },
      ),
  });
}
