import { createTenantLlmSettingsRepository } from "@qmentisai/db";

/**
 * Data access of the tenant AI settings: the tenant-scoped repository of `@qmentisai/db` plus the transaction runner. Every
 * call carries the tenant id from the session.
 * @param {{ db: any }} deps
 */
export function createTenantAiSettingsRepository({ db }) {
  const settings = createTenantLlmSettingsRepository({ db });
  return Object.freeze({
    findSettings: settings.findSettings,
    getConsents: settings.getConsents,
    findConsentChangedBy: settings.findConsentChangedBy,
    setExternalConsent: settings.setExternalConsent,
    setCodeSnippetConsent: settings.setCodeSnippetConsent,
    transaction: (fn) => db.$transaction(fn),
  });
}
