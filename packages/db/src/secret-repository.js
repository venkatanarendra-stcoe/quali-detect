import { assertTenantId } from "./repository.js";
import { withTransaction } from "./transaction.js";

/**
 * Prisma persistence for the SecretStore (ADR-009). Every operation REQUIRES the tenant and puts it in the `where`: a
 * secret or data key is never read, changed or deleted by id alone, and a `secretId` from another tenant simply finds
 * nothing. Rows hold ciphertext only. This is the only code that touches `secrets` and `tenant_data_keys`.
 * @param {{ db: any }} deps Prisma client
 */
export function createSecretRepository({ db }) {
  const isUniqueViolation = (error) => error?.code === "P2002";
  return Object.freeze({
    /** The Prisma client (or transaction client) behind this repository, for the audit write that must share the transaction. */
    client: db,
    /** Runs `fn(repository)` in one transaction, so a secret write and its audit entry commit (or fail) together. */
    transaction: (fn) => withTransaction(db, (tx) => fn(createSecretRepository({ db: tx }))),

    /** @param {{ tenantId: string }} input */
    async findActiveDataKey({ tenantId }) {
      return db.tenantDataKey.findFirst({
        where: { tenantId: assertTenantId(tenantId), status: "active" },
      });
    },
    /** @param {{ tenantId: string, version: number }} input */
    async findDataKey({ tenantId, version }) {
      return db.tenantDataKey.findUnique({
        where: { tenantId_version: { tenantId: assertTenantId(tenantId), version } },
      });
    },
    /**
     * Creates the tenant's first data key. Returns null when a concurrent request created it first (unique violation),
     * so the caller reads the winner instead of failing.
     * @param {{ tenantId: string, version: number, wrappedKey: string, masterKeyVersion: number }} input
     */
    async createDataKey({ tenantId, version, wrappedKey, masterKeyVersion }) {
      try {
        return await db.tenantDataKey.create({
          data: { tenantId: assertTenantId(tenantId), version, wrappedKey, masterKeyVersion },
        });
      } catch (error) {
        if (isUniqueViolation(error)) return null;
        throw error;
      }
    },

    /** @param {{ id: string, tenantId: string, purpose: string, ciphertext: string, nonce: string, dekVersion: number }} row */
    async insertSecret({ id, tenantId, purpose, ciphertext, nonce, dekVersion }) {
      return db.secret.create({
        data: { id, tenantId: assertTenantId(tenantId), purpose, ciphertext, nonce, dekVersion },
      });
    },
    /** Live (not deleted) secret of this tenant, or null. @param {{ tenantId: string, secretId: string }} input */
    async findSecret({ tenantId, secretId }) {
      return db.secret.findFirst({
        where: { id: secretId, tenantId: assertTenantId(tenantId), deletedAt: null },
      });
    },
    /** @param {{ tenantId: string, secretId: string, ciphertext: string, nonce: string, dekVersion: number, rotatedAt: Date }} input @returns {Promise<number>} rows changed */
    async updateSecret({ tenantId, secretId, ciphertext, nonce, dekVersion, rotatedAt }) {
      const { count } = await db.secret.updateMany({
        where: { id: secretId, tenantId: assertTenantId(tenantId), deletedAt: null },
        data: { ciphertext, nonce, dekVersion, rotatedAt },
      });
      return count;
    },
    /** Removes the ciphertext and marks the row deleted. @param {{ tenantId: string, secretId: string, deletedAt: Date }} input @returns {Promise<number>} rows changed */
    async markSecretDeleted({ tenantId, secretId, deletedAt }) {
      const { count } = await db.secret.updateMany({
        where: { id: secretId, tenantId: assertTenantId(tenantId), deletedAt: null },
        data: { ciphertext: "", nonce: "", deletedAt },
      });
      return count;
    },
  });
}
