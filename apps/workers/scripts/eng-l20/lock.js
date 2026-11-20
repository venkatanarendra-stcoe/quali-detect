import { readFileSync } from "node:fs";

const LOCK = new URL(
  "../../src/execution/engines/ensemble/catalog/images.lock.json",
  import.meta.url,
);

/** The pinned entries (key, digest, version) of the committed image lock file. Read-only. */
export function loadLockEntries() {
  return JSON.parse(readFileSync(LOCK, "utf8")).images.map((e) => ({
    key: e.key,
    digest: e.digest,
    version: e.version,
  }));
}
