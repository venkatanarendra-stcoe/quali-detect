import { readFileSync } from "node:fs";

/**
 * PlatformSecretProvider (ADR-009 amendment): named PLATFORM-level secrets that belong to no tenant, such as the GitHub App
 * private key, client secret and webhook secret. They are never stored in the database; the tenant SecretStore is unchanged
 * and is not used for them. Providers: environment (development, optionally `<NAME>_FILE` for a mounted file) and KMS/Vault
 * (production; adapters not implemented yet, so production refuses the environment provider at startup).
 *
 * @typedef {object} PlatformSecretProvider
 * @property {string} kind "env" | "kms" | "vault"
 * @property {(name: string) => string | null} get the secret value or null; never log or return the result
 * @property {(name: string) => boolean} has
 */

/** Secret names and the environment variables that carry them in development. */
export const PLATFORM_SECRET_VARIABLES = Object.freeze({
  "github.app.private_key": "GITHUB_APP_PRIVATE_KEY",
  "github.app.client_secret": "GITHUB_APP_CLIENT_SECRET",
  "github.app.webhook_secret": "GITHUB_APP_WEBHOOK_SECRET",
});

/**
 * Environment-backed provider (DEVELOPMENT). A PEM stored in a single-line variable may use `\n` escapes. If `<VAR>_FILE` is
 * set, the value is read from that file (trailing newline trimmed).
 * @param {{ env?: Record<string, string | undefined> }} [options]
 * @returns {PlatformSecretProvider}
 */
export function createEnvPlatformSecretProvider({ env = process.env } = {}) {
  const read = (name) => {
    const variable = PLATFORM_SECRET_VARIABLES[name];
    if (!variable) throw new TypeError(`Unknown platform secret "${name}".`);
    const file = env[`${variable}_FILE`];
    let value = file ? readFileSync(file, "utf8").replace(/\r?\n$/, "") : env[variable];
    if (typeof value !== "string" || value.trim() === "") return null;
    if (name === "github.app.private_key") value = value.replace(/\\n/g, "\n");
    return value;
  };
  return Object.freeze({
    kind: "env",
    get: read,
    has: (name) => read(name) !== null,
  });
}
