import { createCipheriv, createDecipheriv, randomBytes } from "node:crypto";

const ALGORITHM = "aes-256-gcm";
export const KEY_BYTES = 32;
export const NONCE_BYTES = 12; // 96-bit random nonce, fresh for every encryption
const TAG_BYTES = 16;

/** Raised for any failure that must not reveal why (wrong key, tampered or replayed ciphertext). */
export class SecretCryptoError extends Error {
  constructor(message = "The secret could not be decrypted.") {
    super(message);
    this.name = "SecretCryptoError";
  }
}

/**
 * Additional authenticated data of a secret: tenantId + secretId + purpose + keyVersion (ADR-009). JSON of an array is
 * unambiguous (no separator confusion), and any change of one field makes decryption fail, so a ciphertext cannot be
 * moved to another tenant, record or purpose, nor presented as another key version.
 * @param {{ tenantId: string, secretId: string, purpose: string, keyVersion: number }} fields
 */
export const buildSecretAad = ({ tenantId, secretId, purpose, keyVersion }) =>
  Buffer.from(JSON.stringify([tenantId, secretId, purpose, keyVersion]), "utf8");

/**
 * AES-256-GCM encryption with a fresh random 96-bit nonce.
 * @param {{ key: Buffer, plaintext: Buffer, aad: Buffer }} input
 * @returns {{ nonce: Buffer, ciphertext: Buffer }} `ciphertext` includes the 16-byte authentication tag at its end
 */
export function encryptAesGcm({ key, plaintext, aad }) {
  if (!Buffer.isBuffer(key) || key.length !== KEY_BYTES)
    throw new TypeError(`The encryption key must be ${KEY_BYTES} bytes.`);
  const nonce = randomBytes(NONCE_BYTES);
  const cipher = createCipheriv(ALGORITHM, key, nonce, { authTagLength: TAG_BYTES });
  cipher.setAAD(aad);
  const body = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  return { nonce, ciphertext: Buffer.concat([body, cipher.getAuthTag()]) };
}

/**
 * @param {{ key: Buffer, nonce: Buffer, ciphertext: Buffer, aad: Buffer }} input
 * @returns {Buffer} plaintext
 * @throws {SecretCryptoError} on any authentication or format failure (no detail)
 */
export function decryptAesGcm({ key, nonce, ciphertext, aad }) {
  try {
    if (key.length !== KEY_BYTES || nonce.length !== NONCE_BYTES || ciphertext.length < TAG_BYTES)
      throw new SecretCryptoError();
    const decipher = createDecipheriv(ALGORITHM, key, nonce, { authTagLength: TAG_BYTES });
    decipher.setAAD(aad);
    decipher.setAuthTag(ciphertext.subarray(ciphertext.length - TAG_BYTES));
    return Buffer.concat([
      decipher.update(ciphertext.subarray(0, ciphertext.length - TAG_BYTES)),
      decipher.final(),
    ]);
  } catch {
    throw new SecretCryptoError();
  }
}

export const generateDataKey = () => randomBytes(KEY_BYTES);
