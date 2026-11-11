const DEFAULT_OPTIONS = Object.freeze({ maxWait: 5000, timeout: 15000 });

/**
 * Runs `fn` inside a database transaction (use for every multi-record state change). Everything done through the
 * `tx` argument commits together or rolls back when `fn` throws. If `client` is already a transaction client, `fn` joins
 * it instead of opening a nested transaction.
 * @template T
 * @param {{ $transaction?: Function }} client Prisma client (or transaction client).
 * @param {(tx: any) => Promise<T>} fn
 * @param {{ maxWait?: number, timeout?: number, isolationLevel?: string }} [options] Milliseconds; Prisma isolation level name.
 * @returns {Promise<T>}
 */
export async function withTransaction(client, fn, options = {}) {
  if (typeof client.$transaction !== "function") return fn(client);
  return client.$transaction((tx) => fn(tx), { ...DEFAULT_OPTIONS, ...options });
}
