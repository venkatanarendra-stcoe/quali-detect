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
  /**
   * The trigger router's own queue (docs/modules/pipelines-triggers/SPEC.md §6.2, §9, Q15), hosted by the `pipeline` worker and
   * bound to the SCM events exchange with `PIPELINE_TRIGGERS_BINDINGS`; the `scm-events` queue and the producer are unchanged.
   */
  PIPELINE_TRIGGERS: "pipeline-triggers",
  /** Hint events for Socket.IO (docs/modules/executions/SPEC.md §9.1, §9.3); consumed by the `realtime` worker (part F). */
  REALTIME: "realtime",
  /** Scan tasks of `untrusted_fork` executions: same handler as `scan`, separate consumers (SPEC ER-7, EQ-7b). */
  SCAN_UNTRUSTED: "scan-untrusted",
});

/** Topic exchange for webhook-derived SCM events; routing key `scm.github.<event>` (SPEC Q11). */
export const SCM_EVENTS_EXCHANGE = "qmentis.scm.events";
/** @param {string} event GitHub event name, for example "push" @returns {string} */
export const scmRoutingKey = (event) => `scm.github.${event}`;

/**
 * Topic bindings of the `pipeline-triggers` queue on `SCM_EVENTS_EXCHANGE`: ONLY push and pull-request events (the router never
 * sees repository or installation events). RabbitMQ copies each published event to every bound queue.
 * @type {ReadonlyArray<Readonly<{ exchange: string, routingKey: string }>>}
 */
export const PIPELINE_TRIGGERS_BINDINGS = Object.freeze([
  Object.freeze({ exchange: SCM_EVENTS_EXCHANGE, routingKey: scmRoutingKey("push") }),
  Object.freeze({ exchange: SCM_EVENTS_EXCHANGE, routingKey: scmRoutingKey("pull_request") }),
]);
