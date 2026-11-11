import { ERROR_CODES } from "@qmentisai/contracts";
import { AppError } from "../errors/app-error.js";

/**
 * Progressive brute-force throttling for sign-in and second-factor endpoints (ADR-010, AUTHORIZATION Q24).
 *
 * - Two independent counters, BOTH enforced: per account (the submitted identifier, whether or not such an account
 *   exists, so existing and non-existing accounts behave identically) and per client IP.
 * - Only evaluated FAILURES count. After `freeAttempts` failures the next attempt must wait `baseDelaySeconds`, doubling
 *   with each further failure up to `capSeconds`. There is NO hard lock: the wait never exceeds the cap, attempts refused
 *   during a wait do not extend it, and a success clears the account's counter.
 * - A refused attempt is a `429 RATE_LIMITED` with `details.retryAfterSeconds`, the same body for every identifier.
 * - The IP counter tolerates `ipFreeMultiplier` times the account's free attempts (shared offices and NAT).
 * Uses the shared Redis limiter, or a per-process one in development.
 *
 * @typedef {{ freeAttempts: number, baseDelaySeconds: number, capSeconds: number }} DelayPolicy
 * @param {{
 *   limiter: { blockedFor: Function, recordFailure: Function, clearFailures: Function },
 *   audience: string,
 *   policy: DelayPolicy,
 *   decaySeconds?: number,
 *   ipFreeMultiplier?: number,
 *   onCapReached?: (event: { audience: string, identifier: string, ip: string, scope: "account" | "ip" }) => void,
 * }} options
 */
export function createLoginThrottle({
  limiter,
  audience,
  policy,
  decaySeconds = 86400,
  ipFreeMultiplier = 10,
  onCapReached,
}) {
  const accountBucket = `auth-acct-${audience}`;
  const ipBucket = `auth-ip-${audience}`;
  const ipPolicy = { ...policy, freeAttempts: policy.freeAttempts * ipFreeMultiplier };
  const normalize = (identifier) => String(identifier).trim().toLowerCase();

  return Object.freeze({
    /**
     * Call BEFORE evaluating credentials. Read-only: never extends a wait.
     * @param {{ ip: string, identifier: string }} input
     * @throws {AppError} RATE_LIMITED (429)
     */
    async check({ ip, identifier }) {
      const [byAccount, byIp] = await Promise.all([
        limiter.blockedFor({ bucket: accountBucket, subject: normalize(identifier) }),
        limiter.blockedFor({ bucket: ipBucket, subject: ip }),
      ]);
      const retryAfterSeconds = Math.max(byAccount, byIp);
      if (retryAfterSeconds > 0)
        throw new AppError(
          ERROR_CODES.RATE_LIMITED,
          "Too many sign-in attempts. Try again later.",
          { details: { retryAfterSeconds } },
        );
    },
    /**
     * Call after credentials or a code were evaluated and rejected. Performs the same operations whether or not the
     * account exists; the cap notification runs in the background so it cannot change the response time.
     * @param {{ ip: string, identifier: string }} input
     */
    async recordFailure({ ip, identifier }) {
      const subject = normalize(identifier);
      const [account, byIp] = await Promise.all([
        limiter.recordFailure({ bucket: accountBucket, subject, decaySeconds, ...policy }),
        limiter.recordFailure({ bucket: ipBucket, subject: ip, decaySeconds, ...ipPolicy }),
      ]);
      if (account.capReached)
        onCapReached?.({ audience, identifier: subject, ip, scope: "account" });
      if (byIp.capReached) onCapReached?.({ audience, identifier: subject, ip, scope: "ip" });
    },
    /** Call after a successful sign-in or verification: the account's streak ends (the IP's decays on its own). @param {{ identifier: string }} input */
    async recordSuccess({ identifier }) {
      await limiter.clearFailures({ bucket: accountBucket, subject: normalize(identifier) });
    },
  });
}
