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
 * @param {{ production?: boolean, path?: URL | string }} [options] `production: true` turns unpushed own builds and placeholder digests into errors
 * @returns {{ resolver: ReturnType<typeof createImageResolver>, warnings: string[], sha256: string }} `sha256` is logged at worker start
 * @throws {SandboxError} `invalid_config` when the file is missing, too large, not JSON or fails validation (rule names only)
 */
export function loadImageLock({ production = false, path = IMAGE_LOCK_PATH } = {}) {
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
  const { warnings } = validateImageLock(lock, { production });
  const resolver = createImageResolver(lock, { production });
  return { resolver, warnings, sha256: createHash("sha256").update(text).digest("hex") };
}
