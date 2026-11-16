/**
 * Thrown by a lease holder's write when the execution's lease epoch is no longer the one it holds (the lease was reclaimed or
 * the execution ended; SPEC executions ER-30). The holder must stop at once and write nothing else; the message, if any, is
 * acknowledged. Never retried.
 */
export class LeaseLostError extends Error {
  /** @param {{ executionId?: string, leaseEpoch?: number }} [details] */
  constructor({ executionId, leaseEpoch } = {}) {
    super("The execution lease was lost (reclaimed by another worker or the execution ended).");
    this.name = "LeaseLostError";
    this.code = "LEASE_LOST";
    this.executionId = executionId;
    this.leaseEpoch = leaseEpoch;
  }
}
