import { SANDBOX_ERROR_CODES, SandboxError } from "./errors.js";

/**
 * Counting semaphores for tool runs (SPEC 5.8, SE-19, ENG-S14): per worker, per tenant, per task and the `untrusted_fork` share of
 * the worker. A run holds one unit of EACH applicable limit; a waiter that cannot get all of them before its timeout is refused with
 * `capacity` (the tool becomes `unavailable`, reason `capacity`). FIFO, no starvation of older waiters by younger ones.
 *
 * @param {{ perWorker: number, perTenant: number, perTask: number, forkShare: number }} limits `forkShare` caps concurrent runs of
 *   `untrusted_fork` tasks on this worker; all must be positive integers
 */
export function createCapacityGate(limits) {
  for (const k of ["perWorker", "perTenant", "perTask", "forkShare"])
    if (!Number.isInteger(limits?.[k]) || limits[k] < 1)
      throw new SandboxError(
        SANDBOX_ERROR_CODES.invalidConfig,
        `capacity limit ${k} must be a positive integer`,
        [k],
      );
  let worker = 0;
  let forks = 0;
  const tenants = new Map();
  const tasks = new Map();
  /** @type {Array<{ ref: any, grant: () => void, cancelled: boolean }>} */
  const queue = [];

  const fits = ({ tenantId, taskId, fork }) =>
    worker < limits.perWorker &&
    (tenants.get(tenantId) ?? 0) < limits.perTenant &&
    (tasks.get(taskId) ?? 0) < limits.perTask &&
    (!fork || forks < limits.forkShare);
  const take = ({ tenantId, taskId, fork }) => {
    worker += 1;
    tenants.set(tenantId, (tenants.get(tenantId) ?? 0) + 1);
    tasks.set(taskId, (tasks.get(taskId) ?? 0) + 1);
    if (fork) forks += 1;
  };
  const drop = ({ tenantId, taskId, fork }) => {
    worker -= 1;
    for (const [map, key] of [
      [tenants, tenantId],
      [tasks, taskId],
    ]) {
      const left = (map.get(key) ?? 1) - 1;
      if (left <= 0) map.delete(key);
      else map.set(key, left);
    }
    if (fork) forks -= 1;
  };
  const pump = () => {
    // FIFO with skipping: a waiter blocked only by its own tenant or task limit does not block others
    for (let i = 0; i < queue.length;) {
      const w = queue[i];
      if (w.cancelled) {
        queue.splice(i, 1);
      } else if (fits(w.ref)) {
        queue.splice(i, 1);
        take(w.ref);
        w.grant();
      } else i += 1;
    }
  };

  return Object.freeze({
    /**
     * @param {{ tenantId: string, taskId: string, fork?: boolean }} ref
     * @param {{ timeoutMs: number, signal?: AbortSignal }} options
     * @returns {Promise<() => void>} the release function (idempotent)
     * @throws {SandboxError} `capacity` on timeout or abort
     */
    acquire(ref, { timeoutMs, signal }) {
      const r = { tenantId: ref.tenantId, taskId: ref.taskId, fork: ref.fork === true };
      return new Promise((resolve, reject) => {
        const grant = () => {
          clearTimeout(timer);
          signal?.removeEventListener("abort", fail);
          let released = false;
          resolve(() => {
            if (released) return;
            released = true;
            drop(r);
            pump();
          });
        };
        const waiter = { ref: r, grant, cancelled: false };
        const fail = () => {
          if (waiter.cancelled) return;
          waiter.cancelled = true;
          clearTimeout(timer);
          signal?.removeEventListener("abort", fail);
          reject(
            new SandboxError(SANDBOX_ERROR_CODES.capacity, "no capacity before the timeout", [
              "capacity",
            ]),
          );
        };
        const timer = setTimeout(fail, timeoutMs);
        if (signal?.aborted) return fail();
        signal?.addEventListener("abort", fail, { once: true });
        if (queue.length === 0 && fits(r)) {
          take(r);
          grant();
        } else {
          queue.push(waiter);
          pump();
        }
      });
    },
    snapshot: () => ({
      worker,
      forks,
      tenants: tenants.size,
      tasks: tasks.size,
      waiting: queue.filter((w) => !w.cancelled).length,
    }),
  });
}
