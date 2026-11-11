/**
 * Durable queue names, one per worker type (docs/architecture/WORKER_ARCHITECTURE.md).
 * @type {Readonly<Record<string, string>>}
 */
export const QUEUE_NAMES = Object.freeze({
  PIPELINE: "pipeline",
  ANALYSIS: "analysis",
  SCAN: "scan",
  NOTIFICATION: "notification",
  USAGE: "usage",
  SCHEDULER: "scheduler",
});
