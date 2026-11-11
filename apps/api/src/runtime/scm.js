import { createEnvPlatformSecretProvider, createGitHubClient } from "@qmentisai/infra";

/**
 * Builds the GitHub adapter when `GITHUB_APP_ENABLED` (configuration already validated the settings and refused unsafe
 * secret providers). The App credentials come from the PlatformSecretProvider and are read lazily, never stored in the
 * database and never logged. Missing secrets stop the process at startup (the message names the secret, not its value).
 * @param {{ config: any, logger: import("pino").Logger }} deps
 * @returns {{ github: ReturnType<typeof createGitHubClient>, config: any, secrets: import("@qmentisai/infra").PlatformSecretProvider } | null}
 */
export function createScm({ config, logger }) {
  if (!config.github.enabled) return null;
  const secrets = createEnvPlatformSecretProvider();
  const missing = [
    "github.app.private_key",
    "github.app.client_secret",
    "github.app.webhook_secret",
  ].filter((name) => !secrets.has(name));
  if (missing.length > 0)
    throw new Error(
      `The GitHub integration is enabled but these platform secrets are missing: ${missing.join(", ")}.`,
    );
  const github = createGitHubClient({
    apiBaseUrl: config.github.apiBaseUrl,
    webBaseUrl: config.github.webBaseUrl,
    apiVersion: config.github.apiVersion,
    clientId: config.github.clientId,
    appSlug: config.github.appSlug,
    getPrivateKey: () => secrets.get("github.app.private_key"),
    getClientSecret: () => secrets.get("github.app.client_secret"),
    logger,
  });
  return { github, config: config.github, secrets };
}
