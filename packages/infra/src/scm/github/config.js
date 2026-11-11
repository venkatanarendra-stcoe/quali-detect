/**
 * Reads the GitHub App configuration from an environment object (shared by the API and the workers). Plain validation, no
 * dependency; callers turn the returned problems into their own ConfigError. Secrets are NOT read here: they come from the
 * PlatformSecretProvider. Production refuses the `env` provider (ADR-009 amendment) until a KMS/Vault provider exists.
 * @param {Record<string, string | undefined>} env
 * @param {{ production: boolean }} options
 * @returns {{ enabled: boolean, problems: Array<{ variable: string, message: string }>, config: object | null }}
 */
export function readGitHubAppConfig(env, { production }) {
  const enabled = env.GITHUB_APP_ENABLED === "true";
  if (!enabled) return { enabled: false, problems: [], config: null };
  const problems = [];
  const need = (variable) => {
    const value = env[variable]?.trim();
    if (!value)
      problems.push({ variable, message: "required while the GitHub integration is enabled" });
    return value;
  };
  const url = (variable, fallback) => {
    const value = (env[variable]?.trim() || fallback).replace(/\/+$/, "");
    if (!/^https?:\/\/[^\s]+$/.test(value))
      problems.push({ variable, message: "must be an http(s) URL" });
    return value;
  };
  const provider = env.PLATFORM_SECRET_PROVIDER?.trim() || "env";
  if (!["env", "kms", "vault"].includes(provider))
    problems.push({
      variable: "PLATFORM_SECRET_PROVIDER",
      message: "must be one of: env, kms, vault",
    });
  else if (provider !== "env")
    problems.push({
      variable: "PLATFORM_SECRET_PROVIDER",
      message: `the "${provider}" provider is not implemented yet`,
    });
  else if (production)
    problems.push({
      variable: "PLATFORM_SECRET_PROVIDER",
      message:
        'the "env" provider is development only; production needs a KMS or Vault provider before the GitHub integration can be enabled',
    });
  const int = (variable, fallback, min, max) => {
    const raw = env[variable]?.trim();
    if (!raw) return fallback;
    const value = Number(raw);
    if (!Number.isInteger(value) || value < min || value > max) {
      problems.push({ variable, message: `must be an integer from ${min} to ${max}` });
      return fallback;
    }
    return value;
  };
  const config = {
    appId: need("GITHUB_APP_ID"),
    clientId: need("GITHUB_APP_CLIENT_ID"),
    appSlug: need("GITHUB_APP_SLUG"),
    apiBaseUrl: url("GITHUB_API_BASE_URL", "https://api.github.com"),
    webBaseUrl: url("GITHUB_WEB_BASE_URL", "https://github.com"),
    apiVersion: env.GITHUB_API_VERSION?.trim() || "2026-03-10",
    oauthRedirectUri: need("GITHUB_OAUTH_REDIRECT_URI"),
    setupRedirectUri: env.GITHUB_SETUP_REDIRECT_URI?.trim() || null,
    platformSecretProvider: provider,
    // Reconciliation and sync (SPEC §6.5); all configurable.
    reconcileIntervalSeconds: int("SCM_RECONCILE_INTERVAL_SECONDS", 900, 60, 86400),
    reconcileWindowHours: int("SCM_RECONCILE_WINDOW_HOURS", 70, 1, 71),
    reconcileMaxRedeliveries: int("SCM_RECONCILE_MAX_REDELIVERIES", 50, 1, 1000),
    syncIntervalSeconds: int("SCM_SYNC_INTERVAL_SECONDS", 3600, 60, 604800),
    syncFailuresBeforeDisconnect: int("SCM_SYNC_FAILURES_BEFORE_DISCONNECT", 5, 1, 100),
    deliveryRetentionDays: int("SCM_DELIVERY_RETENTION_DAYS", 30, 1, 3650),
    webhookBodyLimitBytes: int("SCM_WEBHOOK_BODY_LIMIT_BYTES", 1048576, 1024, 26214400),
    webhookInstallationLimitPerMinute: int(
      "SCM_WEBHOOK_INSTALLATION_LIMIT_PER_MINUTE",
      1200,
      10,
      1000000,
    ),
  };
  return { enabled: true, problems, config: problems.length > 0 ? null : Object.freeze(config) };
}
