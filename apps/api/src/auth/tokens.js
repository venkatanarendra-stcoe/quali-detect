import { createHash, randomBytes, timingSafeEqual } from "node:crypto";

const TOKEN_PATTERN = /^[A-Za-z0-9_-]{43}$/;

/** 256-bit random session token (43 base64url characters). Only its hash is ever stored. */
export const generateSessionToken = () => randomBytes(32).toString("base64url");

/** Cheap shape check so junk cookie values never reach the database. @param {unknown} token */
export const isWellFormedToken = (token) => typeof token === "string" && TOKEN_PATTERN.test(token);

/** SHA-256 hex digest stored in `token_hash`. High-entropy tokens need no salt or slow hash. @param {string} token */
export const hashSessionToken = (token) => createHash("sha256").update(token).digest("hex");

/**
 * Constant-time comparison of two secrets of any length (both are hashed first).
 * @param {unknown} a
 * @param {unknown} b
 */
export function secretsMatch(a, b) {
  const digest = (value) =>
    createHash("sha256")
      .update(String(value ?? ""))
      .digest();
  return timingSafeEqual(digest(a), digest(b));
}
