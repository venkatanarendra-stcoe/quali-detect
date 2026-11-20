/**
 * Cooperative yielding for the CPU-heavy loops of the ensemble path (docs/modules/scan-engines/SPEC.md SE-17 to SE-19 and 17.i, owner
 * decision of 2026-11-20): the worker's lease heartbeat is a timer on the SAME event loop as the work, so a long synchronous loop
 * (a merge of tens of thousands of candidates took about 24 s) could starve the heartbeat past the lease TTL and cause a false reclaim.
 *
 * The heavy steps are written ONCE as generator functions that `yield` at a checkpoint (once per candidate, record, group or finding,
 * and inside the long inner scans). Two drivers run the same generator:
 * - {@link runSync} runs it to completion without ever suspending (the pure, synchronous reference; identical results by construction);
 * - {@link runYielding} lets the event loop run (a `setImmediate` turn) whenever a time slice of {@link YIELD_SLICE_MS} has been used up.
 * The checkpoint is cheap (one clock read), the result is byte-identical and deterministic (SE-14) because the order of operations is the
 * generator's, never the driver's. NOT an optimisation: throughput tuning waits for real numbers (ENG-L10). A single native call (one
 * `JSON.parse`, one regular expression pass) cannot be sliced; those are bounded by the input caps and measured (SPEC 17.j).
 */

/** The longest stretch of work between two event-loop turns (milliseconds). */
export const YIELD_SLICE_MS = 8;

/**
 * Runs a checkpointed generator to completion in one synchronous call.
 * @template T
 * @param {Generator<void, T, void>} generator
 * @returns {T}
 */
export function runSync(generator) {
  let step = generator.next();
  while (!step.done) step = generator.next();
  return step.value;
}

/**
 * Runs a checkpointed generator, giving the event loop a turn whenever the current time slice is used up.
 * @template T
 * @param {Generator<void, T, void>} generator
 * @param {{ sliceMs?: number, now?: () => number }} [options] `now` and `sliceMs` exist for the tests only
 * @returns {Promise<T>}
 */
export async function runYielding(
  generator,
  { sliceMs = YIELD_SLICE_MS, now = () => performance.now() } = {},
) {
  let sliceStart = now();
  let step = generator.next();
  while (!step.done) {
    if (now() - sliceStart >= sliceMs) {
      await new Promise((resolve) => setImmediate(resolve));
      sliceStart = now();
    }
    step = generator.next();
  }
  return step.value;
}

/** Items per presorted run, and merge steps between two checkpoints (a native sort of a run this small is far below a slice). */
const SORT_RUN = 256;
const MERGE_STEP = 256;

/**
 * A STABLE sort with checkpoints: native sorts of runs of {@link SORT_RUN} items, then pairwise stable merges that checkpoint every
 * {@link MERGE_STEP} steps. For a consistent comparator the result is identical to `[...items].sort(compare)` (both are stable).
 * @template T
 * @param {readonly T[]} items
 * @param {(a: T, b: T) => number} compare
 * @returns {Generator<void, T[], void>}
 */
export function* sortYielding(items, compare) {
  /** @type {T[][]} */
  let runs = [];
  for (let i = 0; i < items.length; i += SORT_RUN) {
    runs.push(items.slice(i, i + SORT_RUN).sort(compare));
    yield;
  }
  while (runs.length > 1) {
    const next = [];
    for (let r = 0; r < runs.length; r += 2) {
      if (r + 1 === runs.length) {
        next.push(runs[r]);
        continue;
      }
      const left = runs[r];
      const right = runs[r + 1];
      const out = [];
      let a = 0;
      let b = 0;
      let steps = 0;
      while (a < left.length && b < right.length) {
        // stable: on a tie the left (earlier) item goes first
        out.push(compare(left[a], right[b]) <= 0 ? left[a++] : right[b++]);
        steps += 1;
        if (steps % MERGE_STEP === 0) yield;
      }
      while (a < left.length) out.push(left[a++]);
      while (b < right.length) out.push(right[b++]);
      next.push(out);
      yield;
    }
    runs = next;
  }
  return runs[0] ?? [];
}
