/**
 * Progressive delay curve shared by the Redis and in-memory limiters.
 *
 * After `freeAttempts` failures the next attempt must wait `baseDelaySeconds`; every further failure doubles the wait up
 * to `capSeconds`. There is NO hard lock: the wait never exceeds the cap, and only failures that were actually evaluated
 * count (attempts refused during a wait do not extend it), so an attacker can slow an account but not lock it out.
 * @typedef {{ freeAttempts: number, baseDelaySeconds: number, capSeconds: number }} DelayPolicy
 * @param {number} failures consecutive failures so far (including the one just recorded)
 * @param {DelayPolicy} policy
 * @returns {number} seconds the next attempt must wait (0 = none)
 */
export function progressiveDelaySeconds(failures, { freeAttempts, baseDelaySeconds, capSeconds }) {
  if (failures <= freeAttempts) return 0;
  const exponent = Math.min(failures - freeAttempts - 1, 30);
  return Math.min(capSeconds, baseDelaySeconds * 2 ** exponent);
}

/**
 * The failure count at which the delay first equals the cap (used to emit the "cap reached" notification exactly once
 * per streak).
 * @param {DelayPolicy} policy
 */
export function capReachedAtFailure(policy) {
  let failures = policy.freeAttempts + 1;
  while (progressiveDelaySeconds(failures, policy) < policy.capSeconds) failures += 1;
  return failures;
}

/** @param {DelayPolicy} policy */
export function assertDelayPolicy({ freeAttempts, baseDelaySeconds, capSeconds }) {
  if (!Number.isInteger(freeAttempts) || freeAttempts < 0)
    throw new RangeError("freeAttempts must be a non-negative integer");
  if (!Number.isInteger(baseDelaySeconds) || baseDelaySeconds < 1)
    throw new RangeError("baseDelaySeconds must be a positive integer");
  if (!Number.isInteger(capSeconds) || capSeconds < baseDelaySeconds)
    throw new RangeError("capSeconds must be an integer >= baseDelaySeconds");
}
