import { randomUUID } from "node:crypto";
import { buildLockKey, buildPlatformKey } from "@qmentisai/shared";

const RELEASE_SCRIPT = `if redis.call("get", KEYS[1]) == ARGV[1] then return redis.call("del", KEYS[1]) else return 0 end`;
const EXTEND_SCRIPT = `if redis.call("get", KEYS[1]) == ARGV[1] then return redis.call("pexpire", KEYS[1], ARGV[2]) else return 0 end`;

/** Thrown by `withLock` when the lock could not be acquired in time. */
export class LockNotAcquiredError extends Error {
  constructor(resource) {
    super(`Could not acquire lock for ${resource}.`);
    this.name = "LockNotAcquiredError";
  }
}

const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

/**
 * Distributed lock manager on a single Redis (SET NX PX with an owner token; release and extend only if still owner).
 * Limits: this is a lease on one Redis instance, not a consensus lock; a paused holder can outlive its TTL, so protect
 * critical writes with database constraints/transactions too. Tenant locks require `tenantId`; platform locks use the
 * explicit `acquirePlatform`.
 * @param {{ redis: import("ioredis").Redis }} options
 */
export function createLockManager({ redis }) {
  async function acquireKey(key, resource, { ttlMs = 30000, waitMs = 0, retryDelayMs = 100 }) {
    if (!Number.isInteger(ttlMs) || ttlMs < 1)
      throw new RangeError("ttlMs must be a positive integer");
    const token = randomUUID();
    const deadline = Date.now() + waitMs;
    for (;;) {
      if ((await redis.set(key, token, "PX", ttlMs, "NX")) === "OK") {
        return Object.freeze({
          resource,
          /** @returns {Promise<boolean>} whether this holder still owned the lock. */
          release: async () => (await redis.eval(RELEASE_SCRIPT, 1, key, token)) === 1,
          /** @param {number} [extraMs] New TTL from now. @returns {Promise<boolean>} */
          extend: async (extraMs = ttlMs) =>
            (await redis.eval(EXTEND_SCRIPT, 1, key, token, extraMs)) === 1,
        });
      }
      if (Date.now() >= deadline) return null;
      await sleep(Math.min(retryDelayMs, Math.max(deadline - Date.now(), 1)));
    }
  }

  const manager = {
    /**
     * @param {{ tenantId: string, resource: string, ttlMs?: number, waitMs?: number, retryDelayMs?: number }} options
     * @returns {Promise<{ resource: string, release: () => Promise<boolean>, extend: (ms?: number) => Promise<boolean> } | null>} null when still held by someone else after `waitMs`.
     */
    acquire: (options) => acquireKey(buildLockKey(options), options.resource, options),
    /** Lock on platform-owned work (not tenant data). @param {{ resource: string, ttlMs?: number, waitMs?: number, retryDelayMs?: number }} options */
    acquirePlatform: (options) =>
      acquireKey(
        buildPlatformKey({ namespace: "lock", parts: [options.resource] }),
        options.resource,
        options,
      ),
    /**
     * Runs `fn` while holding the tenant lock; always releases. Throws `LockNotAcquiredError` if it cannot be acquired.
     * @template T
     * @param {{ tenantId: string, resource: string, ttlMs?: number, waitMs?: number }} options
     * @param {(lock: { extend: (ms?: number) => Promise<boolean> }) => Promise<T>} fn
     * @returns {Promise<T>}
     */
    async withLock(options, fn) {
      const lock = await manager.acquire(options);
      if (!lock) throw new LockNotAcquiredError(options.resource);
      try {
        return await fn(lock);
      } finally {
        await lock.release();
      }
    },
  };
  return Object.freeze(manager);
}
