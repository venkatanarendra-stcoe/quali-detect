import { createHash } from "node:crypto";

/**
 * Stable, key-safe digest of an arbitrary string (email, IP address, URL...) for use as a key segment.
 * @param {string} value
 * @returns {string} 32 hex characters
 */
export function hashKeyPart(value) {
  return createHash("sha256").update(String(value)).digest("hex").slice(0, 32);
}
