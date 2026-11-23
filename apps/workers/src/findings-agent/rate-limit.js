import { ADVISORY_TENANT_CALLS_PER_MINUTE } from "./constants.js";

/**
 * The per-tenant request limiter of the advisory agent on Redis (SPEC 9.3.5: a token bucket of 30 per minute and tenant). It adapts the
 * shared fixed-window limiter of `@qmentisai/infra` (`createRateLimiter`, injected: this module imports nothing) to the agent's
 * `{ tryAcquire(tenantId) }` port. The key is tenant scoped by the shared key builder (`rl:<tenant>:<bucket>:<hash>`), so one tenant's
 * burst never spends another tenant's allowance. A Redis failure propagates: the queue retries the message, and nothing is stored.
 * @param {{ limiter: { consume: (o: { tenantId: string, bucket: string, subject: string, limit: number, windowSeconds: number }) => Promise<{ allowed: boolean }> }, perMinute?: number }} deps
 * @returns {{ tryAcquire: (tenantId: string) => Promise<boolean> }}
 */
export function createRedisTenantRateLimiter({
  limiter,
  perMinute = ADVISORY_TENANT_CALLS_PER_MINUTE,
}) {
  return Object.freeze({
    async tryAcquire(tenantId) {
      const result = await limiter.consume({
        tenantId,
        bucket: "findings-agent",
        subject: tenantId,
        limit: perMinute,
        windowSeconds: 60,
      });
      return result.allowed === true;
    },
  });
}
