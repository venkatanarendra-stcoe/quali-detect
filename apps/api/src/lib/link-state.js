import { createHash, randomBytes } from "node:crypto";
import { buildTenantKey } from "@qmentisai/shared";

const TTL_SECONDS = 600;
const sha = (value) => createHash("sha256").update(value).digest("hex").slice(0, 32);

/**
 * Single-use `state` for the GitHub installation-linking flow (SPEC R-2). The state is random, only its hash is stored, and
 * the Redis key is TENANT-scoped, so a state created in one tenant can never be consumed in another. `consume` deletes the
 * record atomically (GETDEL), so a state works once. Redis-backed; in-process fallback for development without Redis.
 * @param {{ infra: { redis: any }, now?: () => number }} deps
 */
export function createLinkStateStore({ infra, now = Date.now }) {
  const memory = new Map();
  const keyOf = (tenantId, state) =>
    buildTenantKey({ tenantId, namespace: "scm-link-state", parts: [sha(state)] });
  return Object.freeze({
    /** @param {{ tenantId: string, userId: string, sessionId: string, installationId: string }} binding @returns {Promise<string>} the state */
    async create(binding) {
      const state = randomBytes(32).toString("base64url");
      const key = keyOf(binding.tenantId, state);
      const value = JSON.stringify({
        userId: binding.userId,
        sessionId: binding.sessionId,
        installationId: binding.installationId,
      });
      if (infra.redis) await infra.redis.set(key, value, "EX", TTL_SECONDS);
      else memory.set(key, { value, expiresAt: now() + TTL_SECONDS * 1000 });
      return state;
    },
    /** Returns the binding and removes it, or null when unknown, expired or already used. @param {{ tenantId: string, state: string }} input */
    async consume({ tenantId, state }) {
      const key = keyOf(tenantId, state);
      let raw = null;
      if (infra.redis) raw = await infra.redis.getdel(key);
      else {
        const entry = memory.get(key);
        memory.delete(key);
        raw = entry && entry.expiresAt > now() ? entry.value : null;
      }
      return raw ? JSON.parse(raw) : null;
    },
  });
}
