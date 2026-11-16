/**
 * Engine registry and adapter contract (docs/modules/executions/SPEC.md ER-6, HX-1). SHAPE ONLY: no engine ships with the
 * platform yet (EXEC-026, EQ-7a), so the registry is empty in production and the orchestrator claims only executions whose
 * enabled scan types all have a registered engine. The only adapter that exists is the deterministic test adapter of the
 * security suite.
 *
 * An adapter is `{ scanType, engineId, version, idempotent, runTask }` with
 * `runTask(context, { signal, log, emit }) -> { status: "succeeded" | "failed", items?, summary? }`:
 * - `context` is the frozen, credential-free ScanContext (ids, scan type, engine, thresholds, deadline, the directory of the
 *   extracted archive). It never contains a token, a SecretStore handle or a URL with credentials (ER-5);
 * - it MUST honour `signal` (aborted at the task deadline, on lease loss and on cancel) and write logs only through `log`;
 * - it MUST NOT execute, import, build or install anything from the archive (R-8): static analysis only;
 * - `emit(item)` reports an item as soon as it is found, so a timeout keeps the partial result;
 * - it throws `EngineError` to classify a failure.
 * `idempotent: true` is a promise that re-running the task has no side effect (all v1 adapters must be: read-only analysis).
 */

/** A classified engine failure: `permanent` (never retried) or `transient` (retried while attempts remain). */
export class EngineError extends Error {
  /** @param {string} code stable code `^[a-z][a-z_:]{0,63}$` @param {"permanent" | "transient"} errorClass */
  constructor(code, errorClass = "permanent") {
    super(code);
    this.name = "EngineError";
    this.code = code;
    this.errorClass = errorClass;
  }
}

/** @returns {ReturnType<typeof createEngineRegistry>} */
export function createEngineRegistry() {
  /** @type {Map<string, { scanType: string, engineId: string, version: string, idempotent: boolean, runTask: Function }>} */
  const engines = new Map();
  const key = (scanType, engineId) => `${scanType}:${engineId}`;
  return Object.freeze({
    /** @param {{ scanType: string, engineId: string, version: string, idempotent?: boolean, runTask: Function }} adapter */
    register(adapter) {
      if (
        typeof adapter?.runTask !== "function" ||
        !adapter.scanType ||
        !adapter.engineId ||
        !adapter.version
      )
        throw new TypeError("An engine adapter needs scanType, engineId, version and runTask.");
      engines.set(
        key(adapter.scanType, adapter.engineId),
        Object.freeze({ idempotent: false, ...adapter }),
      );
    },
    has: (scanType, engineId) => engines.has(key(scanType, engineId)),
    get: (scanType, engineId) => engines.get(key(scanType, engineId)) ?? null,
    get size() {
      return engines.size;
    },
  });
}
