import { createSign } from "node:crypto";

const b64url = (input) => Buffer.from(input).toString("base64url");

/**
 * GitHub App JSON Web Token (RS256), per the documentation verified in the spike: claims `iat` (60 s in the past against
 * clock drift), `exp` (at most 10 minutes ahead) and `iss` (the client ID, or the app ID). Sent as `Authorization: Bearer`.
 * @param {{ issuer: string, privateKeyPem: string, now?: () => number, ttlSeconds?: number }} input `now` in milliseconds
 * @returns {{ token: string, expiresAt: Date }}
 */
export function createAppJwt({ issuer, privateKeyPem, now = Date.now, ttlSeconds = 540 }) {
  if (ttlSeconds < 1 || ttlSeconds > 600)
    throw new RangeError("A GitHub App JWT may live at most 10 minutes.");
  const issuedAt = Math.floor(now() / 1000) - 60;
  const expiresAt = issuedAt + 60 + ttlSeconds;
  const header = b64url(JSON.stringify({ alg: "RS256", typ: "JWT" }));
  const payload = b64url(JSON.stringify({ iat: issuedAt, exp: expiresAt, iss: String(issuer) }));
  const signature = createSign("RSA-SHA256")
    .update(`${header}.${payload}`)
    .sign(privateKeyPem)
    .toString("base64url");
  return { token: `${header}.${payload}.${signature}`, expiresAt: new Date(expiresAt * 1000) };
}
