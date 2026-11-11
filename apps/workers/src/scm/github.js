import { createEnvPlatformSecretProvider, createGitHubClient } from "@qmentisai/infra";

/**
 * The worker's GitHub adapter. Credentials come from the PlatformSecretProvider; the worker refuses to start without them
 * (the message names the missing secret, never a value). Installation tokens are minted in this process and kept in memory.
 * @param {{ config: any, logger: any }} deps
 */
export function createWorkerGitHub({ config, logger }) {
  if (!config.scm.enabled)
    throw new Error("The scm worker needs GITHUB_APP_ENABLED=true and the GitHub App settings.");
  const secrets = createEnvPlatformSecretProvider();
  const missing = ["github.app.private_key", "github.app.client_secret"].filter(
    (name) => !secrets.has(name),
  );
  if (missing.length > 0)
    throw new Error(
      `The GitHub integration is enabled but these platform secrets are missing: ${missing.join(", ")}.`,
    );
  return createGitHubClient({
    apiBaseUrl: config.scm.apiBaseUrl,
    webBaseUrl: config.scm.webBaseUrl,
    apiVersion: config.scm.apiVersion,
    clientId: config.scm.clientId,
    appSlug: config.scm.appSlug,
    getPrivateKey: () => secrets.get("github.app.private_key"),
    getClientSecret: () => secrets.get("github.app.client_secret"),
    logger,
  });
}
