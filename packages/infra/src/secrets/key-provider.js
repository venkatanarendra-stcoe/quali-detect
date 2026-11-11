import { KEY_BYTES, SecretCryptoError, decryptAesGcm, encryptAesGcm } from "./crypto.js";

/**
 * Raised when the master key configuration is unusable. The message names the problem, NEVER the key.
 */
export class SecretConfigError extends Error {
  constructor(message) {
    super(message);
    this.name = "SecretConfigError";
  }
}

/**
 * Parses and validates a base64 master key: it must decode to EXACTLY 32 bytes (AES-256). Call at startup so a wrong key
 * stops the process instead of failing on first use.
 * @param {string | undefined} base64
 * @returns {Buffer}
 * @throws {SecretConfigError}
 */
export function parseMasterKey(base64) {
  if (typeof base64 !== "string" || base64.trim() === "")
    throw new SecretConfigError("The master key is not set.");
  const normalized = base64.trim();
  if (!/^[A-Za-z0-9+/]+={0,2}$/.test(normalized))
    throw new SecretConfigError("The master key must be base64.");
  const key = Buffer.from(normalized, "base64");
  if (key.length !== KEY_BYTES)
    throw new SecretConfigError(`The master key must decode to exactly ${KEY_BYTES} bytes.`);
  return key;
}

/**
 * KeyProvider contract (ADR-009): wraps and unwraps tenant data keys with the master key (KEK). A KMS or Vault adapter
 * implements the same three members, so switching changes configuration, not callers.
 * @typedef {object} KeyProvider
 * @property {() => number} currentVersion version of the master key used for new wraps
 * @property {(input: { tenantId: string, dekVersion: number, dek: Buffer }) => Promise<{ wrapped: string, masterKeyVersion: number }>} wrap
 * @property {(input: { tenantId: string, dekVersion: number, wrapped: string, masterKeyVersion: number }) => Promise<Buffer>} unwrap
 */

const wrapAad = ({ tenantId, dekVersion, masterKeyVersion }) =>
  Buffer.from(JSON.stringify(["dek", tenantId, dekVersion, masterKeyVersion]), "utf8");

/**
 * DEVELOPMENT key provider: the master key comes from the environment. Not for production (config refuses it there).
 * The unwrapped data key is returned to the caller and never kept.
 * @param {{ masterKey: Buffer, version?: number }} options `masterKey` from `parseMasterKey`
 * @returns {KeyProvider}
 */
export function createEnvKeyProvider({ masterKey, version = 1 }) {
  if (!Buffer.isBuffer(masterKey) || masterKey.length !== KEY_BYTES)
    throw new SecretConfigError(`The master key must be ${KEY_BYTES} bytes.`);
  if (!Number.isInteger(version) || version < 1)
    throw new SecretConfigError("The master key version must be a positive integer.");
  return Object.freeze({
    currentVersion: () => version,
    async wrap({ tenantId, dekVersion, dek }) {
      const { nonce, ciphertext } = encryptAesGcm({
        key: masterKey,
        plaintext: dek,
        aad: wrapAad({ tenantId, dekVersion, masterKeyVersion: version }),
      });
      return {
        wrapped: Buffer.concat([nonce, ciphertext]).toString("base64"),
        masterKeyVersion: version,
      };
    },
    async unwrap({ tenantId, dekVersion, wrapped, masterKeyVersion }) {
      if (masterKeyVersion !== version)
        throw new SecretCryptoError(
          "The data key was wrapped by a master key version that is not configured.",
        );
      const bytes = Buffer.from(wrapped, "base64");
      return decryptAesGcm({
        key: masterKey,
        nonce: bytes.subarray(0, 12),
        ciphertext: bytes.subarray(12),
        aad: wrapAad({ tenantId, dekVersion, masterKeyVersion }),
      });
    },
  });
}
