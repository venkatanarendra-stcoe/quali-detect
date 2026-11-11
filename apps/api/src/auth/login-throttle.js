import { ERROR_CODES } from "@qmentisai/contracts";
import { AppError } from "../errors/app-error.js";

/**
 * Brute-force protection for login endpoints: every attempt (success or failure) counts against the caller's IP and
 * against IP + account, in a fixed window. Uses the shared Redis limiter, or a per-process one in development.
 * @param {{ limiter: { consumeGlobal: Function }, audience: "tenant" | "platform", windowSeconds?: number, perIdentity?: number, perIp?: number }} options
 */
export function createLoginThrottle({
  limiter,
  audience,
  windowSeconds = 900,
  perIdentity = 10,
  perIp = 50,
}) {
  return Object.freeze({
    /**
     * @param {{ ip: string, identifier: string }} input
     * @throws {AppError} RATE_LIMITED (429) when a limit is exceeded
     */
    async check({ ip, identifier }) {
      const byIp = await limiter.consumeGlobal({
        bucket: `login-ip-${audience}`,
        subject: ip,
        limit: perIp,
        windowSeconds,
      });
      const byIdentity = await limiter.consumeGlobal({
        bucket: `login-id-${audience}`,
        subject: `${ip}|${identifier}`,
        limit: perIdentity,
        windowSeconds,
      });
      const blocked = [byIp, byIdentity].filter((r) => !r.allowed);
      if (blocked.length > 0) {
        const retryAfterSeconds = Math.max(...blocked.map((r) => r.resetSeconds));
        throw new AppError(
          ERROR_CODES.RATE_LIMITED,
          "Too many sign-in attempts. Try again later.",
          { details: { retryAfterSeconds } },
        );
      }
    },
  });
}
