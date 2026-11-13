import { createHash, createHmac, hkdfSync, timingSafeEqual } from "node:crypto";
import { InvalidCursorError } from "./keyset.js";

/**
 * Keyed signing of pagination cursors (docs/technical/API_STANDARDS.md "Cursor pagination").
 *
 * Token (before base64url): `[format 1 byte][key id 1 byte][HMAC-SHA256 32 bytes][payload]`.
 * - Each configured secret (`CURSOR_SIGNING_SECRET`, newest first) is never used directly: a purpose-specific subkey is
 *   derived with HKDF-SHA256 over the fixed label `qmentis:cursor:v1`.
 * - The key id is the first byte of SHA-256(subkey): a fingerprint, so a verifier picks the right key without the list
 *   changing meaning when secrets are added or removed. Rotation: put the new secret FIRST (it signs), keep the old one
 *   after it until its cursors have expired in practice, then drop it. A cursor signed with a key that is no longer listed
 *   fails like any forged cursor (400 INVALID_CURSOR); the client restarts its walk.
 * - The MAC covers label, format, key id, the request binding (endpoint, scope, sort, filters, parent) and the payload.
 *   Verification is constant-time.
 */

const LABEL = "qmentis:cursor:v1";
const FORMAT = 1;
const MAC_BYTES = 32;
const HEADER_BYTES = 2 + MAC_BYTES;

/** @type {Array<{ id: number, key: Buffer }> | null} */
let keyring = null;

/**
 * Installs the signing keys (called once by `createApp`). The first secret signs; all verify.
 * @param {readonly string[]} secrets
 */
export function configureCursorSigning(secrets) {
  if (secrets.length === 0) throw new Error("At least one cursor signing secret is required.");
  keyring = secrets.map((secret) => {
    const key = Buffer.from(
      hkdfSync("sha256", Buffer.from(secret, "utf8"), Buffer.alloc(0), LABEL, 32),
    );
    return { id: createHash("sha256").update(key).digest()[0], key };
  });
}

const macOf = (key, format, keyId, binding, payload) =>
  createHmac("sha256", key)
    .update(Buffer.from([format, keyId]))
    .update(`${LABEL}\n${binding}\n`)
    .update(payload)
    .digest();

/**
 * @param {{ binding: string, payload: Buffer }} input
 * @returns {string} base64url token
 */
export function signCursor({ binding, payload }) {
  if (!keyring) throw new Error("Cursor signing is not configured.");
  const { id, key } = keyring[0];
  const mac = macOf(key, FORMAT, id, binding, payload);
  return Buffer.concat([Buffer.from([FORMAT, id]), mac, payload]).toString("base64url");
}

/**
 * @param {{ token: string, binding: string }} input
 * @returns {Buffer} the authenticated payload
 * @throws {InvalidCursorError} for anything not signed by a listed key for exactly this binding
 */
export function verifyCursor({ token, binding }) {
  if (!keyring) throw new Error("Cursor signing is not configured.");
  const raw = Buffer.from(token, "base64url");
  if (raw.length <= HEADER_BYTES || raw[0] !== FORMAT) throw new InvalidCursorError();
  const given = raw.subarray(2, HEADER_BYTES);
  const payload = raw.subarray(HEADER_BYTES);
  let valid = false;
  for (const { id, key } of keyring) {
    if (id !== raw[1]) continue;
    const expected = macOf(key, FORMAT, id, binding, payload);
    if (timingSafeEqual(expected, given)) valid = true;
  }
  if (!valid) throw new InvalidCursorError();
  return Buffer.from(payload);
}
