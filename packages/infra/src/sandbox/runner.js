import { LABEL_KEYS } from "./policy.js";
import { containerNameOf } from "./run-spec.js";

/**
 * The per-attempt runner (SPEC 6.4): runs tool containers through a SandboxRuntime and guarantees that an abort (user cancel, lease
 * loss, task deadline) kills and then removes EVERY container of the attempt exactly once, including containers started by a
 * previous holder of the same process that are still listed by label.
 *
 * @param {{ runtime: import("./runtime.js").SandboxRuntime }} options
 */
export function createSandboxRunner({ runtime }) {
  /** @type {Map<string, Set<string>>} attempt key -> container names started and not yet reaped */
  const started = new Map();
  const keyOf = (taskId, attempt) => `${taskId}#${attempt}`;

  return Object.freeze({
    /**
     * Runs one tool container. The container name is registered before the runtime is called, so an abort between "registered" and
     * "started" still removes it.
     * @param {import("./run-spec.js").RunSpec} spec
     * @param {{ signal?: AbortSignal }} [options]
     */
    async runTool(spec, options = {}) {
      const key = keyOf(spec.labels.taskId, spec.labels.attempt);
      const name = containerNameOf(spec);
      if (!started.has(key)) started.set(key, new Set());
      started.get(key).add(name);
      try {
        return await runtime.run(spec, options);
      } finally {
        started.get(key)?.delete(name);
        if (started.get(key)?.size === 0) started.delete(key);
      }
    },

    /**
     * Kills and removes every container of one attempt: the ones this runner started and every container the runtime lists with
     * the task and attempt labels. Each container is killed and removed exactly once per call.
     * @param {{ taskId: string, attempt: number }} ref
     * @returns {Promise<{ reaped: string[], failed: string[] }>}
     */
    async abortAttempt({ taskId, attempt }) {
      const names = new Set(started.get(keyOf(taskId, attempt)) ?? []);
      const listed = await runtime
        .listByLabel({
          [LABEL_KEYS.scan]: "1",
          [LABEL_KEYS.task]: taskId,
          [LABEL_KEYS.attempt]: String(attempt),
        })
        .catch(() => []);
      for (const c of listed) names.add(c.name);
      const reaped = [];
      const failed = [];
      for (const name of names) {
        try {
          await runtime.kill(name);
          await runtime.remove(name);
          reaped.push(name);
        } catch {
          failed.push(name);
        }
      }
      return { reaped, failed };
    },

    /** @param {{ taskId: string, attempt: number }} ref */
    activeCount: ({ taskId, attempt }) => started.get(keyOf(taskId, attempt))?.size ?? 0,
  });
}
