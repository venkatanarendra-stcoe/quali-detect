import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import {
  SANDBOX_ERROR_CODES,
  SandboxError,
  createImageResolver,
  validateImageLock,
} from "@qmentisai/infra";

/**
 * Loader of the reviewed image lock file (docs/modules/scan-engines/IMAGE_CATALOG.md, SPEC 9.3). Reads the file next to this module,
 * validates it and returns the resolver the sandbox runner uses. Nothing here talks to a container runtime or a registry.
 */

export const IMAGE_LOCK_PATH = new URL("./images.lock.json", import.meta.url);
const MAX_LOCK_BYTES = 262144;

/**
 * @param {{ production?: boolean, path?: URL | string, localImages?: Record<string, string> }} [options] `production: true` turns unpushed own builds and placeholder digests into errors.
 *   `localImages` (B2 of the E2E run) is the DEVELOPMENT path for the own-built images: a map of lock key to the local image repository
 *   (`opengrep` to `qm-spike-opengrep`); each such entry is resolved as `repository@<source.localImageId>`, the id the lock records for
 *   the local build. It is REFUSED in production and for a key that is not an own build, and nothing else of the lock changes.
 * @returns {{ resolver: ReturnType<typeof createImageResolver>, warnings: string[], sha256: string }} `sha256` is logged at worker start
 * @throws {SandboxError} `invalid_config` when the file is missing, too large, not JSON or fails validation (rule names only)
 */
export function loadImageLock({
  production = false,
  path = IMAGE_LOCK_PATH,
  localImages = {},
} = {}) {
  let text;
  try {
    text = readFileSync(path, "utf8");
  } catch {
    throw new SandboxError(SANDBOX_ERROR_CODES.invalidConfig, "image lock file cannot be read", [
      "images.lock.json",
    ]);
  }
  if (Buffer.byteLength(text) > MAX_LOCK_BYTES)
    throw new SandboxError(SANDBOX_ERROR_CODES.invalidConfig, "image lock file is too large", [
      "images.lock.json",
    ]);
  let lock;
  try {
    lock = JSON.parse(text);
  } catch {
    throw new SandboxError(SANDBOX_ERROR_CODES.invalidConfig, "image lock file is not valid JSON", [
      "images.lock.json",
    ]);
  }
  if (Object.keys(localImages).length > 0) {
    if (production)
      throw new SandboxError(
        SANDBOX_ERROR_CODES.invalidConfig,
        "local image overrides are refused in production",
        ["SCAN_ENGINES_LOCAL_IMAGES"],
      );
    for (const [key, repository] of Object.entries(localImages)) {
      const entry = (lock.images ?? []).find((e) => e.key === key);
      if (
        !entry ||
        entry.source?.kind !== "own_build" ||
        !entry.source.localImageId ||
        entry.digest
      )
        throw new SandboxError(
          SANDBOX_ERROR_CODES.invalidConfig,
          "a local image override needs an own build with a recorded local image id and no registry digest",
          ["SCAN_ENGINES_LOCAL_IMAGES"],
        );
      entry.repository = repository;
      entry.digest = entry.source.localImageId;
      entry.flags = (entry.flags ?? []).filter((f) => f !== "local_build_requires_registry_digest");
    }
  }
  const { warnings } = validateImageLock(lock, { production });
  const resolver = createImageResolver(lock, { production });
  return { resolver, warnings, sha256: createHash("sha256").update(text).digest("hex") };
}
