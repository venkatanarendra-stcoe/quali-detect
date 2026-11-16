import { createExecutionLogRepository } from "@qmentisai/db";
import { createLogStore } from "@qmentisai/infra";

/**
 * The LogStore of a worker: the Postgres driver over the capped tables, with the configured caps
 * (docs/modules/executions/SPEC.md §17.ac). Workers build it from their own database client unless one is injected.
 * @param {{ db: any, config: any, logStore?: any }} deps
 */
export function resolveLogStore({ db, config, logStore }) {
  return (
    logStore ??
    createLogStore({
      repository: createExecutionLogRepository({ db }),
      limits: config.execution.logs,
    })
  );
}

/**
 * The buffered log writer of ONE task attempt. The engine's `log(level, message)` is synchronous, so lines are queued in memory
 * (at most `maxPending`, the rest counted and dropped) and flushed in batches by a timer or when a batch is full; `close()`
 * flushes what is left and MUST be awaited before the task is finished (a finished task is no longer `running`, so the fence
 * would refuse the writes). A flush never throws: a failure is counted, a fenced answer stops the writer for good (the attempt
 * is not ours any more), and logging can never fail the task. Every line still passes the LogStore's redaction.
 * @param {{ logStore: any, ref: { tenantId: string, executionId: string, taskId: string, attempt: number, workerId: string }, logger?: any, flushMs?: number, batch?: number, maxPending?: number }} deps
 */
export function createTaskLogWriter({
  logStore,
  ref,
  logger,
  flushMs = 1000,
  batch = 100,
  maxPending = 1000,
}) {
  let pending = [];
  let lost = false;
  let overflow = 0;
  let chain = Promise.resolve();
  let timer = null;

  const flush = () => {
    chain = chain.then(async () => {
      if (lost || pending.length === 0) return;
      const lines = pending;
      pending = [];
      try {
        for (let i = 0; i < lines.length && !lost; i += batch) {
          const result = await logStore.appendTask(ref, lines.slice(i, i + batch));
          if (result.fenced) lost = true;
        }
      } catch (error) {
        logger?.warn?.(
          { taskId: ref.taskId, errorName: error?.name },
          "Task log lines could not be stored",
        );
      }
    });
    return chain;
  };

  return Object.freeze({
    /** Queues one line (never throws, never waits). @param {string} level @param {unknown} message */
    log(level, message) {
      if (lost) return;
      if (pending.length >= maxPending) {
        overflow += 1;
        return;
      }
      pending.push({ level, message });
      if (pending.length >= batch) void flush();
      else
        timer ??= setTimeout(() => {
          timer = null;
          void flush();
        }, flushMs).unref?.();
    },
    /** Flushes what is queued and stops the timer; resolves when the lines are stored. */
    async close() {
      if (timer) clearTimeout(timer);
      timer = null;
      if (overflow > 0) {
        pending.push({
          level: "warn",
          message: `${overflow} log lines were dropped before they could be stored`,
        });
        overflow = 0;
      }
      await flush();
      await chain;
    },
  });
}
