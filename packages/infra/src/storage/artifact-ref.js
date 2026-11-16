/**
 * The ONE place that validates and builds an artifact reference (docs/modules/executions/SPEC.md §7.5, §17.ac), shared by every
 * `ArtifactStore` driver (local-fs, Postgres, and the object-storage adapter that is still Open). The logical key of an object
 * is `t/<tenantId>/x/<executionId>/<name>`: the tenant is in every key, the caller never supplies a path, and `name` is ONE
 * path segment (lowercase letters, digits, `.`, `_`, `-`; it starts with a letter, has no `..` and does not end with `.`), so
 * it can neither traverse nor name a hidden file. The database repeats the name rule as a CHECK.
 */

const SEGMENT = /^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/;
/** An artifact name: one segment, `^[a-z][a-z0-9._-]{0,63}$`, no `..`, no trailing dot. */
export const ARTIFACT_NAME_PATTERN = /^[a-z][a-z0-9._-]{0,63}$/;

/**
 * Whether `name` is a valid artifact name (the traversal guard).
 * @param {unknown} name
 * @returns {boolean}
 */
export function isValidArtifactName(name) {
  return (
    typeof name === "string" &&
    ARTIFACT_NAME_PATTERN.test(name) &&
    !name.includes("..") &&
    !name.endsWith(".")
  );
}

/**
 * Validates a reference and returns its logical key. Throws `TypeError` for anything that is not a plain tenant id, execution
 * id and artifact name (separators, `..`, empty, non-strings, over-long values).
 * @param {{ tenantId: string, executionId: string, name: string }} ref
 * @returns {{ tenantId: string, executionId: string, name: string, key: string }}
 */
export function parseArtifactRef(ref) {
  const { tenantId, executionId, name } = ref ?? {};
  if (
    typeof tenantId !== "string" ||
    typeof executionId !== "string" ||
    !SEGMENT.test(tenantId) ||
    !SEGMENT.test(executionId) ||
    tenantId.includes("..") ||
    executionId.includes("..") ||
    !isValidArtifactName(name)
  )
    throw new TypeError("Invalid artifact reference.");
  return { tenantId, executionId, name, key: `t/${tenantId}/x/${executionId}/${name}` };
}

/**
 * The methods every `ArtifactStore` driver implements (the interface a later object-storage adapter must satisfy).
 * `put(ref, stream, { maxBytes, ifAbsent })`, `open(ref)`, `size(ref)`, `sha256(ref)`, `delete(ref)`, `deleteExecution(ref)`
 * and `keyFor(ref)`; `kind` names the driver.
 */
export const ARTIFACT_STORE_METHODS = Object.freeze([
  "put",
  "open",
  "size",
  "sha256",
  "delete",
  "deleteExecution",
  "keyFor",
]);

/**
 * Throws when `store` does not implement the `ArtifactStore` interface.
 * @param {any} store
 * @returns {any} the same store
 */
export function assertArtifactStore(store) {
  if (!store || typeof store.kind !== "string")
    throw new TypeError("An ArtifactStore needs a string `kind`.");
  for (const method of ARTIFACT_STORE_METHODS)
    if (typeof store[method] !== "function")
      throw new TypeError(`The ArtifactStore "${store.kind}" does not implement ${method}().`);
  return store;
}
