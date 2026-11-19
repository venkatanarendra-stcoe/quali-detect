import { LABEL_KEYS } from "./policy.js";

/**
 * The orphan janitor (SPEC 6.4). It lists containers labelled `qm.scan=1` and removes any whose deadline passed or whose attempt
 * is no longer running. It NEVER touches an unlabelled container: the list is filtered by label in the runtime AND re-checked here.
 *
 * @param {{
 *   runtime: import("./runtime.js").SandboxRuntime,
 *   isAttemptRunning: (ref: { tenantId: string, executionId: string, taskId: string, attempt: number }) => Promise<boolean>,
 *   now?: () => number,
 *   graceSeconds?: number,
 *   onError?: (event: { name: string, code: string }) => void
 * }} options `isAttemptRunning` reads the database by (tenant, task, attempt); if it throws, the container is KEPT (fail safe: the
 * next sweep decides) except when its deadline has already passed.
 */
export function createJanitor({
  runtime,
  isAttemptRunning,
  now = Date.now,
  graceSeconds = 0,
  onError = () => {},
}) {
  return Object.freeze({
    /** @returns {Promise<{ listed: number, removed: string[], kept: number, failed: number }>} */
    async sweep() {
      const listed = await runtime.listByLabel({ [LABEL_KEYS.scan]: "1" });
      const removed = [];
      let kept = 0;
      let failed = 0;
      const nowSeconds = Math.floor(now() / 1000);
      for (const c of listed) {
        if (c.labels[LABEL_KEYS.scan] !== "1") continue; // defence in depth: never an unlabelled container
        const deadline = Number(c.labels[LABEL_KEYS.deadline]);
        const attempt = Number(c.labels[LABEL_KEYS.attempt]);
        const malformed =
          !Number.isInteger(deadline) || !Number.isInteger(attempt) || !c.labels[LABEL_KEYS.task];
        let remove = malformed || nowSeconds > deadline + graceSeconds;
        if (!remove) {
          try {
            remove = !(await isAttemptRunning({
              tenantId: c.labels[LABEL_KEYS.tenant],
              executionId: c.labels[LABEL_KEYS.execution],
              taskId: c.labels[LABEL_KEYS.task],
              attempt,
            }));
          } catch {
            remove = false;
          }
        }
        if (!remove) {
          kept += 1;
          continue;
        }
        try {
          await runtime.kill(c.name);
          await runtime.remove(c.name);
          removed.push(c.name);
        } catch (err) {
          failed += 1;
          onError({ name: c.name, code: err?.code ?? "error" });
        }
      }
      return { listed: listed.length, removed, kept, failed };
    },
  });
}
