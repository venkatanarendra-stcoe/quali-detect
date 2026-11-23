import { LLMError } from "@qmentisai/infra";
import { ADVISORY_TENANT_CALLS_PER_MINUTE } from "./constants.js";

/**
 * Cost and rate controls (docs/modules/findings/SPEC.md 9.3.5). Small, dependency-free, per process. The Redis-backed per-tenant bucket
 * of production is bound by the integration through the same `{ tryAcquire(tenantId) }` port.
 */

/**
 * A counting semaphore: at most `max` runs at once (FINDINGS_AGENT_MAX_CONCURRENT_CALLS); waiting honours the abort signal.
 * @param {number} max
 * @returns {{ run: <T>(signal: AbortSignal | undefined, fn: () => Promise<T>) => Promise<T> }}
 */
export function createConcurrencyLimiter(max) {
  if (!Number.isInteger(max) || max < 1) throw new TypeError("max must be a positive integer.");
  let active = 0;
  /** @type {Array<() => void>} */
  const queue = [];
  return Object.freeze({
    async run(signal, fn) {
      if (active >= max) {
        await new Promise((resolve, reject) => {
          const entry = () => {
            signal?.removeEventListener("abort", onAbort);
            resolve(undefined);
          };
          const onAbort = () => {
            const i = queue.indexOf(entry);
            if (i >= 0) queue.splice(i, 1);
            reject(new LLMError("aborted"));
          };
          if (signal?.aborted) return onAbort();
          signal?.addEventListener("abort", onAbort, { once: true });
          queue.push(entry);
        });
      }
      active += 1;
      try {
        return await fn();
      } finally {
        active -= 1;
        queue.shift()?.();
      }
    },
  });
}

/**
 * A per-tenant token bucket (default 30 per minute). The key is the tenant id of the finding ROW, never of a message.
 * @param {{ perMinute?: number, now?: () => number }} [options]
 * @returns {{ tryAcquire: (tenantId: string) => Promise<boolean> }}
 */
export function createTenantTokenBucket({
  perMinute = ADVISORY_TENANT_CALLS_PER_MINUTE,
  now = Date.now,
} = {}) {
  /** @type {Map<string, { tokens: number, at: number }>} */
  const buckets = new Map();
  return Object.freeze({
    async tryAcquire(tenantId) {
      const t = now();
      const b = buckets.get(tenantId) ?? { tokens: perMinute, at: t };
      b.tokens = Math.min(perMinute, b.tokens + ((t - b.at) / 60_000) * perMinute);
      b.at = t;
      const granted = b.tokens >= 1;
      if (granted) b.tokens -= 1;
      buckets.set(tenantId, b);
      return granted;
    },
  });
}

/** Start of the UTC day of `now` (the window of the per-tenant daily cap). @param {Date} now */
export const startOfUtcDay = (now) =>
  new Date(Date.UTC(now.getUTCFullYear(), now.getUTCMonth(), now.getUTCDate()));
