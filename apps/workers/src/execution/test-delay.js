/**
 * TEST-ONLY delay hook (owner decision 2026-11-17, SPEC executions §16.1). It exists for one purpose: to open a window
 * between "the task is running" and "the engine starts", so a live test can exercise running-cancel, task timeout and
 * lease reclaim (SBOM finishes in milliseconds). It is NOT an engine and is NOT in the engine registry.
 *
 * Hard gates:
 *  - `loadTestDelay` THROWS when `NODE_ENV=production` and the variable is set (and `loadWorkerConfig` refuses the same
 *    combination at startup), so a production process cannot start with it;
 *  - the module is only ever loaded by a dynamic `import()` when `EXECUTION_TEST_DELAY_MS` is set, so with the variable
 *    unset it is never read and nothing changes;
 *  - the delay is abortable (the cancel / deadline `AbortSignal`), never longer than 10 minutes, and logs a warning.
 */
export const TEST_DELAY_MAX_MS = 600000;

/**
 * @param {Record<string, string | undefined>} [env]
 * @param {{ warn?: (obj: object, msg: string) => void }} [logger]
 * @returns {((signal: AbortSignal) => Promise<void>) | null} null when the hook is not requested
 */
export function loadTestDelay(env = process.env, logger) {
  const raw = env.EXECUTION_TEST_DELAY_MS;
  if (raw === undefined || raw === "" || raw === "0") return null;
  if (env.NODE_ENV === "production")
    throw new Error(
      "EXECUTION_TEST_DELAY_MS is a test-only hook and is refused when NODE_ENV=production",
    );
  const ms = Number(raw);
  if (!Number.isInteger(ms) || ms < 1 || ms > TEST_DELAY_MAX_MS)
    throw new Error(`EXECUTION_TEST_DELAY_MS must be an integer from 1 to ${TEST_DELAY_MAX_MS}`);
  logger?.warn?.(
    { delayMs: ms },
    "TEST-ONLY execution delay hook is active (EXECUTION_TEST_DELAY_MS)",
  );
  return (signal) =>
    new Promise((resolve, reject) => {
      if (signal?.aborted) return reject(signal.reason);
      const timer = setTimeout(() => {
        signal?.removeEventListener("abort", onAbort);
        resolve();
      }, ms);
      const onAbort = () => {
        clearTimeout(timer);
        reject(signal.reason);
      };
      signal?.addEventListener("abort", onAbort, { once: true });
    });
}
