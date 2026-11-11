import { AppError } from "../../../errors/app-error.js";
import { ERROR_CODES } from "@qmentisai/contracts";

/**
 * Policies of the identity module. Login is the only unauthenticated operation; it is allowed only through an enabled provider.
 */
export const identityPolicy = Object.freeze({
  /** @param {ReadonlyMap<string, unknown>} providers @param {string} providerId */
  assertProviderAvailable(providers, providerId) {
    if (!providers.has(providerId)) {
      throw new AppError(ERROR_CODES.SERVICE_UNAVAILABLE, "No sign-in method is available.");
    }
  },
});
