import { createHash, randomBytes } from "node:crypto";
import { buildTenantKey } from "@qmentisai/shared";

/** Default lifetime of a linking state: 10 minutes (SPEC §18.6). Configurable with `SCM_LINK_STATE_TTL_SECONDS`. */
export const DEFAULT_LINK_STATE_TTL_SECONDS = 600;
const sha = (value) => createHash("sha256").update(value).digest("hex").slice(0, 32);

/**
 * Single-use `state` for the GitHub installation-linking flow (SPEC R-2, §18 A8). The state is random, only its hash is
 * stored, and the Redis key is TENANT-scoped, so a state created in one tenant can never be consumed in another. The stored
 * binding carries user, session, installation AND the workspace: consuming takes the workspace only from here. `consume`
 * deletes the record atomically (GETDEL), so a state works once; it also expires after `ttlSeconds`. Redis-backed;
 * in-process fallback for development without Redis.
 * @param {{ infra: { redis: any }, ttlSeconds?: number, now?: () => number }} deps
 */
export function createLinkStateStore({
  infra,
  ttlSeconds = DEFAULT_LINK_STATE_TTL_SECONDS,
  now = Date.now,
}) {
  const memory = new Map();
  const keyOf = (tenantId, state) =>
    buildTenantKey({ tenantId, namespace: "scm-link-state", parts: [sha(state)] });
  return Object.freeze({
    /** @param {{ tenantId: string, workspaceId: string, userId: string, sessionId: string, installationId: string }} binding @returns {Promise<string>} the state */
    async create(binding) {
      const state = randomBytes(32).toString("base64url");
      const key = keyOf(binding.tenantId, state);
      const value = JSON.stringify({
        workspaceId: binding.workspaceId,
        userId: binding.userId,
        sessionId: binding.sessionId,
        installationId: binding.installationId,
      });
      if (infra.redis) await infra.redis.set(key, value, "EX", ttlSeconds);
      else {
        for (const [k, entry] of memory) if (entry.expiresAt <= now()) memory.delete(k);
        memory.set(key, { value, expiresAt: now() + ttlSeconds * 1000 });
      }
      return state;
    },
    /**
     * Returns the binding (`workspaceId`, `userId`, `sessionId`, `installationId`) and removes it, or null when unknown,
     * expired or already used.
     * @param {{ tenantId: string, state: string }} input
     */
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
