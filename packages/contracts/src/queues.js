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
  /** GitHub jobs: repository sync, delivery reconciliation, retention (docs/modules/repositories-github/SPEC.md). */
  SCM: "scm",
  /** The single consumer that applies normalized SCM events (SPEC §9). */
  SCM_EVENTS: "scm-events",
});

/** Topic exchange for webhook-derived SCM events; routing key `scm.github.<event>` (SPEC Q11). */
export const SCM_EVENTS_EXCHANGE = "qmentis.scm.events";
/** @param {string} event GitHub event name, for example "push" @returns {string} */
export const scmRoutingKey = (event) => `scm.github.${event}`;
