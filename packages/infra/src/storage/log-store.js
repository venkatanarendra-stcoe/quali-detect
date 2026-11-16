import { sanitizeLogMessage } from "./log-redaction.js";

/**
 * The methods every `LogStore` driver implements (the interface a later object-storage driver must satisfy):
 * `appendTask(ref, lines)`, `appendExecution(ref, lines)` and `read(query)`; `kind` names the driver.
 */
export const LOG_STORE_METHODS = Object.freeze(["appendTask", "appendExecution", "read"]);

/**
 * Throws when `store` does not implement the `LogStore` interface.
 * @param {any} store
 * @returns {any} the same store
 */
export function assertLogStore(store) {
  if (!store || typeof store.kind !== "string")
    throw new TypeError("A LogStore needs a string `kind`.");
  for (const method of LOG_STORE_METHODS)
    if (typeof store[method] !== "function")
      throw new TypeError(`The LogStore "${store.kind}" does not implement ${method}().`);
  return store;
}

/** Lines per repository call (the repository accepts at most 500). */
const CHUNK = 200;
const LIMIT_KEYS = [
  "maxLinesPerExecution",
  "maxBytesPerExecution",
  "maxLinesPerTask",
  "maxBytesPerTask",
];

/**
 * Validates the configured caps (positive integers) and freezes them.
 * @param {Record<string, number>} limits
 */
export function parseLogLimits(limits) {
  for (const key of LIMIT_KEYS)
    if (!Number.isInteger(limits?.[key]) || limits[key] < 2)
      throw new TypeError(`The log limit ${key} must be an integer of at least 2.`);
  return Object.freeze(Object.fromEntries(LIMIT_KEYS.map((key) => [key, limits[key]])));
}

/**
 * The `LogStore` of execution logs (docs/modules/executions/SPEC.md §7.4, §17.ac), Postgres driver: the interface hides the
 * capped tables, so an object-storage driver can replace it without changing a caller. EVERY line passes `sanitizeLogMessage`
 * here (credentials redacted, control characters removed, per-line cap) before the repository sees it; the repository then
 * enforces the per-task and per-execution caps (truncation marker + `truncated` flag) and the writer fences. Append never throws
 * for a lost fence: it answers `fenced: true` and the writer must stop.
 * @param {{ repository: ReturnType<typeof import("@qmentisai/db").createExecutionLogRepository>, limits: Record<string, number> }} deps
 */
export function createLogStore({ repository, limits }) {
  const caps = parseLogLimits(limits);
  const prepare = (lines, source) =>
    (Array.isArray(lines) ? lines : []).flatMap((line) =>
      sanitizeLogMessage(line).map((clean) => ({ ...clean, source })),
    );
  /**
   * Writes the prepared lines in chunks the repository accepts, in order, and adds the answers up. A fenced answer ends the
   * write: nothing more is sent for a writer that does not hold the task any more.
   */
  async function inChunks(prepared, write) {
    const total = { appended: 0, dropped: 0, truncated: false, fenced: false };
    for (let i = 0; i === 0 || i < prepared.length; i += CHUNK) {
      const part = await write(prepared.slice(i, i + CHUNK));
      total.appended += part.appended;
      total.dropped += part.dropped;
      total.truncated ||= part.truncated;
      if (part.fenced) return { ...total, fenced: true };
    }
    return total;
  }
  return Object.freeze({
    kind: "postgres",

    /**
     * Appends lines of a RUNNING task attempt (source `scan`). Fenced by `(task, attempt, worker)`: a superseded attempt or a
     * worker that lost the task writes nothing (`fenced: true`).
     * @param {{ tenantId: string, executionId: string, taskId: string, attempt: number, workerId: string }} ref
     * @param {Array<{ level?: string, message: unknown }>} lines
     * @returns {Promise<{ appended: number, dropped: number, truncated: boolean, fenced: boolean }>}
     */
    appendTask: (ref, lines) =>
      inChunks(prepare(lines, "scan"), (part) =>
        repository.appendTaskLines({ ...ref, lines: part, limits: caps }),
      ),

    /**
     * Appends execution-level lines (source `platform` or `fetch`) for the holder of the execution lease. Fenced by the
     * lease epoch (`LeaseLostError` when it is lost, like every lease-holder write).
     * @param {{ tenantId: string, executionId: string, leaseEpoch: number, source?: "platform" | "fetch" }} ref
     * @param {Array<{ level?: string, message: unknown }>} lines
     * @param {any} [client] a transaction client to join
     */
    appendExecution: ({ source = "platform", ...ref }, lines, client) =>
      inChunks(prepare(lines, source === "fetch" ? "fetch" : "platform"), (part) =>
        repository.appendExecutionLines({ ...ref, lines: part, limits: caps }, client),
      ),

    /**
     * Reads lines after `afterSeq` (keyset on `seq`), scoped by tenant (and workspace and task when given).
     * @param {{ tenantId: string, workspaceId?: string, executionId: string, taskId?: string, afterSeq?: number, limit?: number }} query
     */
    read: (query) => repository.listLines(query),
  });
}
