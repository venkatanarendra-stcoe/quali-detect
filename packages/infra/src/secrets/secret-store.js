import { randomUUID } from "node:crypto";
import {
  SecretCryptoError,
  buildSecretAad,
  decryptAesGcm,
  encryptAesGcm,
  generateDataKey,
} from "./crypto.js";

/** The secret does not exist for this tenant (or was deleted). Deliberately identical for "wrong tenant" and "no such id". */
export class SecretNotFoundError extends Error {
  constructor() {
    super("The secret was not found.");
    this.name = "SecretNotFoundError";
  }
}

/** Audit action names written by the store. */
export const SECRET_AUDIT_ACTIONS = Object.freeze({
  CREATED: "secret.created",
  ROTATED: "secret.rotated",
  DELETED: "secret.deleted",
});

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const requireTenant = (tenantId) => {
  if (typeof tenantId !== "string" || !UUID.test(tenantId))
    throw new TypeError("tenantId is required (a UUID from the trusted context).");
  return tenantId;
};
const requirePurpose = (purpose) => {
  if (typeof purpose !== "string" || !/^[a-z][a-z0-9_.-]{0,99}$/.test(purpose))
    throw new TypeError("purpose is required (lowercase letters, digits, '.', '_' or '-').");
  return purpose;
};
const requireValue = (plaintext) => {
  if (typeof plaintext !== "string" || plaintext.length === 0 || plaintext.length > 65536)
    throw new TypeError("The secret value must be a non-empty string of at most 64 KiB.");
  return plaintext;
};
const requireRef = (secretRef) => {
  if (typeof secretRef !== "string" || !UUID.test(secretRef)) throw new SecretNotFoundError();
  return secretRef.toLowerCase();
};

/**
 * @typedef {{ userId?: string, platformUserId?: string, system?: string }} SecretActor who performs the operation (audited)
 * @typedef {object} SecretAuditEvent
 * @property {string} action one of SECRET_AUDIT_ACTIONS
 * @property {string} tenantId
 * @property {SecretActor} actor
 * @property {string} secretRef
 * @property {string} purpose
 * @property {{ dekVersion: number, masterKeyVersion: number }} keyVersions
 *
 * @typedef {object} SecretRepository the persistence contract (implemented over Prisma in @qmentisai/db)
 * @property {(fn: (repository: SecretRepository) => Promise<any>) => Promise<any>} transaction
 */

/**
 * The only way to store, read, rotate and delete credentials (ADR-009). Envelope encryption: each secret is encrypted with
 * AES-256-GCM under its tenant's data key (DEK); the DEK is stored only wrapped by the master key (KeyProvider). The AAD
 * binds every ciphertext to tenantId + secretId + purpose + DEK version.
 *
 * Plaintext rules: `put`/`rotate` take it, only `resolve` returns it (to the calling process), nothing else ever exposes,
 * logs or audits it. Callers pass the `tenantId` of the TRUSTED context; a secretRef of another tenant behaves exactly like
 * a missing one. Create, rotate and delete write an audit entry in the same transaction as the change (audit failure rolls it back).
 *
 * @param {{
 *   repository: SecretRepository & Record<string, Function>,
 *   keyProvider: import("./key-provider.js").KeyProvider,
 *   audit: (event: SecretAuditEvent, options: { tx: any }) => Promise<void>,
 *   clock?: () => Date,
 * }} deps
 */
export function createSecretStore({ repository, keyProvider, audit, clock = () => new Date() }) {
  /** The tenant's active DEK, creating it (wrapped) on first use. Returns the raw key for this operation only. */
  async function activeDataKey(repo, tenantId) {
    let row = await repo.findActiveDataKey({ tenantId });
    if (!row) {
      const dek = generateDataKey();
      const { wrapped, masterKeyVersion } = await keyProvider.wrap({
        tenantId,
        dekVersion: 1,
        dek,
      });
      row = await repo.createDataKey({
        tenantId,
        version: 1,
        wrappedKey: wrapped,
        masterKeyVersion,
      });
      row ??= await repo.findActiveDataKey({ tenantId }); // a concurrent request created it first
      if (!row) throw new SecretCryptoError("No data key is available for this tenant.");
    }
    return {
      dek: await unwrap(tenantId, row),
      version: row.version,
      masterKeyVersion: row.masterKeyVersion,
    };
  }
  const unwrap = (tenantId, row) =>
    keyProvider.unwrap({
      tenantId,
      dekVersion: row.version,
      wrapped: row.wrappedKey,
      masterKeyVersion: row.masterKeyVersion,
    });

  const seal = ({ dek, plaintext, tenantId, secretId, purpose, keyVersion }) => {
    const { nonce, ciphertext } = encryptAesGcm({
      key: dek,
      plaintext: Buffer.from(plaintext, "utf8"),
      aad: buildSecretAad({ tenantId, secretId, purpose, keyVersion }),
    });
    return { nonce: nonce.toString("base64"), ciphertext: ciphertext.toString("base64") };
  };

  const toMetadata = (row) => ({
    secretRef: row.id,
    purpose: row.purpose,
    createdAt: row.createdAt,
    rotatedAt: row.rotatedAt,
    dekVersion: row.dekVersion,
  });

  return Object.freeze({
    /**
     * Encrypts and stores a new secret.
     * @param {{ tenantId: string, purpose: string, plaintext: string, actor: SecretActor }} input
     * @returns {Promise<{ secretRef: string }>}
     */
    async put({ tenantId, purpose, plaintext, actor }) {
      requireTenant(tenantId);
      requirePurpose(purpose);
      requireValue(plaintext);
      const secretId = randomUUID();
      return repository.transaction(async (repo) => {
        const key = await activeDataKey(repo, tenantId);
        const sealed = seal({
          dek: key.dek,
          plaintext,
          tenantId,
          secretId,
          purpose,
          keyVersion: key.version,
        });
        await repo.insertSecret({
          id: secretId,
          tenantId,
          purpose,
          dekVersion: key.version,
          ...sealed,
        });
        await audit(
          {
            action: SECRET_AUDIT_ACTIONS.CREATED,
            tenantId,
            actor,
            secretRef: secretId,
            purpose,
            keyVersions: { dekVersion: key.version, masterKeyVersion: key.masterKeyVersion },
          },
          { tx: repo.client },
        );
        key.dek.fill(0);
        return { secretRef: secretId };
      });
    },

    /**
     * Decrypts a secret for use in THIS process. `purpose` must match the one it was stored with (it is part of the AAD).
     * Another tenant's secretRef, a wrong purpose, a deleted secret and a malformed ref are all refused, without
     * revealing which. Not audited per call (see ADR-009 Open table); never log the return value.
     * @param {{ tenantId: string, secretRef: string, purpose: string }} input
     * @returns {Promise<string>} plaintext
     */
    async resolve({ tenantId, secretRef, purpose }) {
      requireTenant(tenantId);
      requirePurpose(purpose);
      const secretId = requireRef(secretRef);
      const row = await repository.findSecret({ tenantId, secretId });
      if (!row || row.purpose !== purpose) throw new SecretNotFoundError();
      const keyRow = await repository.findDataKey({ tenantId, version: row.dekVersion });
      if (!keyRow) throw new SecretCryptoError();
      const dek = await unwrap(tenantId, keyRow);
      try {
        return decryptAesGcm({
          key: dek,
          nonce: Buffer.from(row.nonce, "base64"),
          ciphertext: Buffer.from(row.ciphertext, "base64"),
          aad: buildSecretAad({
            tenantId,
            secretId,
            purpose: row.purpose,
            keyVersion: row.dekVersion,
          }),
        }).toString("utf8");
      } finally {
        dek.fill(0);
      }
    },

    /**
     * Replaces the value under the same secretRef with a fresh nonce and the tenant's current DEK version.
     * @param {{ tenantId: string, secretRef: string, plaintext: string, actor: SecretActor }} input
     */
    async rotate({ tenantId, secretRef, plaintext, actor }) {
      requireTenant(tenantId);
      requireValue(plaintext);
      const secretId = requireRef(secretRef);
      return repository.transaction(async (repo) => {
        const row = await repo.findSecret({ tenantId, secretId });
        if (!row) throw new SecretNotFoundError();
        const key = await activeDataKey(repo, tenantId);
        const sealed = seal({
          dek: key.dek,
          plaintext,
          tenantId,
          secretId,
          purpose: row.purpose,
          keyVersion: key.version,
        });
        const changed = await repo.updateSecret({
          tenantId,
          secretId,
          dekVersion: key.version,
          rotatedAt: clock(),
          ...sealed,
        });
        if (changed === 0) throw new SecretNotFoundError();
        await audit(
          {
            action: SECRET_AUDIT_ACTIONS.ROTATED,
            tenantId,
            actor,
            secretRef: secretId,
            purpose: row.purpose,
            keyVersions: { dekVersion: key.version, masterKeyVersion: key.masterKeyVersion },
          },
          { tx: repo.client },
        );
        key.dek.fill(0);
        return { secretRef: secretId };
      });
    },

    /** Removes the ciphertext; the reference stops resolving immediately. @param {{ tenantId: string, secretRef: string, actor: SecretActor }} input */
    async delete({ tenantId, secretRef, actor }) {
      requireTenant(tenantId);
      const secretId = requireRef(secretRef);
      return repository.transaction(async (repo) => {
        const row = await repo.findSecret({ tenantId, secretId });
        if (!row) throw new SecretNotFoundError();
        const changed = await repo.markSecretDeleted({ tenantId, secretId, deletedAt: clock() });
        if (changed === 0) throw new SecretNotFoundError();
        await audit(
          {
            action: SECRET_AUDIT_ACTIONS.DELETED,
            tenantId,
            actor,
            secretRef: secretId,
            purpose: row.purpose,
            keyVersions: { dekVersion: row.dekVersion, masterKeyVersion: null },
          },
          { tx: repo.client },
        );
      });
    },

    /**
     * Metadata only (never the value or any fragment of it). Key versions are for internal use and must not be exposed by APIs.
     * @param {{ tenantId: string, secretRef: string }} input
     */
    async describe({ tenantId, secretRef }) {
      requireTenant(tenantId);
      const row = await repository.findSecret({ tenantId, secretId: requireRef(secretRef) });
      if (!row) throw new SecretNotFoundError();
      return toMetadata(row);
    },
  });
}

/**
 * The public, write-only view of a secret for API responses: reference, purpose and timestamps. No value, no key versions.
 * @param {{ secretRef: string, purpose: string, createdAt: Date, rotatedAt: Date | null }} metadata
 */
export const toSecretResponse = ({ secretRef, purpose, createdAt, rotatedAt }) => ({
  secretRef,
  purpose,
  createdAt: createdAt instanceof Date ? createdAt.toISOString() : createdAt,
  rotatedAt: rotatedAt instanceof Date ? rotatedAt.toISOString() : rotatedAt,
});

const FORBIDDEN_MESSAGE_KEYS =
  /^(plaintext|secret|secretValue|password|passwd|token|accessToken|refreshToken|apiKey|privateKey|clientSecret|masterKey|dek)$/i;
/**
 * Guard for queue messages and events: they carry `{ tenantId, secretRef }`, never a credential. Throws when a payload has
 * a key that looks like a secret value (checked recursively).
 * @param {unknown} payload
 * @throws {TypeError}
 */
export function assertSecretFreeMessage(payload, path = "message") {
  if (Array.isArray(payload))
    return payload.forEach((item, i) => assertSecretFreeMessage(item, `${path}[${i}]`));
  if (!payload || typeof payload !== "object") return;
  for (const [key, value] of Object.entries(payload)) {
    if (FORBIDDEN_MESSAGE_KEYS.test(key))
      throw new TypeError(
        `${path}.${key}: credentials must not travel in messages; send a secretRef instead.`,
      );
    assertSecretFreeMessage(value, `${path}.${key}`);
  }
}

/**
 * Worker-side resolution by reference: validates the message, then resolves with the MESSAGE's tenant. The worker must
 * already have revalidated that the integration belongs to that tenant (TENANT_ISOLATION); a foreign secretRef fails here too.
 * @param {ReturnType<typeof createSecretStore>} store
 * @param {{ tenantId: string, secretRef: string }} message
 * @param {{ purpose: string }} options
 */
export function resolveFromMessage(store, message, { purpose }) {
  assertSecretFreeMessage(message);
  return store.resolve({ tenantId: message?.tenantId, secretRef: message?.secretRef, purpose });
}
