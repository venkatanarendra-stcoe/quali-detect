import { PIPELINE_TRIGGERS_BINDINGS, QUEUE_NAMES, SCM_EVENTS_EXCHANGE } from "@qmentisai/contracts";
import { backoffCeilingMs } from "./retry.js";

/**
 * Broker topology per queue `<q>` (names are derived, never hand-written):
 * - exchange `qmentis.jobs`  (direct)  -> queue `qmentis.<q>`        routing key `<q>`
 * - exchange `qmentis.retry` (direct)  -> queues `qmentis.<q>.retry.<n>` (n = 1..maxAttempts-1, TTL = backoff ceiling of retry n,
 *   dead-lettering back to `qmentis.jobs` with key `<q>`); each message also carries its own jittered `expiration`
 * - exchange `qmentis.dlx`   (direct)  -> queue `qmentis.<q>.dlq`    routing key `<q>` (terminal failures, kept for inspection)
 * RabbitMQ expires per-message TTLs only at the head of a queue, so a tier delays a message by at most the tier's ceiling.
 */
export const EXCHANGES = Object.freeze({
  JOBS: "qmentis.jobs",
  RETRY: "qmentis.retry",
  DEAD_LETTER: "qmentis.dlx",
});

export const mainQueueName = (queue) => `qmentis.${queue}`;
export const deadLetterQueueName = (queue) => `qmentis.${queue}.dlq`;
export const retryQueueName = (queue, tier) => `qmentis.${queue}.retry.${tier}`;
export const retryRoutingKey = (queue, tier) => `${queue}.${tier}`;

const QUEUE_NAME = /^[a-z][a-z0-9-]{0,63}$/;

/**
 * THE broker topology: the single definition every process that touches the broker declares at startup (API publisher,
 * outbox relay, every worker). Derived from the queue catalogue in `@qmentisai/contracts`; nothing else declares exchanges,
 * queues or bindings. Declarations are idempotent and their arguments are fixed here, so processes never disagree.
 * - `exchanges`: the three direct exchanges above plus the topic exchange of normalized SCM events.
 * - `queues`: every worker queue (main + retry tiers + DLQ) and the extra TOPIC bindings of its main queue
 *   (`scm-events` <- `scm.github.#`; `pipeline-triggers` <- push and pull_request).
 */
export const BROKER_TOPOLOGY = Object.freeze({
  exchanges: Object.freeze([
    ...Object.values(EXCHANGES).map((name) => Object.freeze({ name, type: "direct" })),
    Object.freeze({ name: SCM_EVENTS_EXCHANGE, type: "topic" }),
  ]),
  queues: Object.freeze(
    Object.values(QUEUE_NAMES).map((queue) =>
      Object.freeze({
        queue,
        bindings: Object.freeze(
          queue === QUEUE_NAMES.SCM_EVENTS
            ? [{ exchange: SCM_EVENTS_EXCHANGE, routingKey: "scm.github.#" }]
            : queue === QUEUE_NAMES.PIPELINE_TRIGGERS
              ? [...PIPELINE_TRIGGERS_BINDINGS]
              : [],
        ),
      }),
    ),
  ),
});

async function declareQueue(channel, { queue, bindings }, retryPolicy) {
  if (!QUEUE_NAME.test(queue)) throw new TypeError(`Invalid queue name "${queue}"`);
  await channel.assertQueue(deadLetterQueueName(queue), { durable: true });
  await channel.bindQueue(deadLetterQueueName(queue), EXCHANGES.DEAD_LETTER, queue);

  await channel.assertQueue(mainQueueName(queue), {
    durable: true,
    arguments: {
      "x-dead-letter-exchange": EXCHANGES.DEAD_LETTER,
      "x-dead-letter-routing-key": queue,
    },
  });
  await channel.bindQueue(mainQueueName(queue), EXCHANGES.JOBS, queue);
  for (const binding of bindings)
    await channel.bindQueue(mainQueueName(queue), binding.exchange, binding.routingKey);

  for (let tier = 1; tier < retryPolicy.maxAttempts; tier += 1) {
    const ttl = backoffCeilingMs({
      attempt: tier,
      baseDelayMs: retryPolicy.baseDelayMs,
      maxDelayMs: retryPolicy.maxDelayMs,
    });
    await channel.assertQueue(retryQueueName(queue, tier), {
      durable: true,
      arguments: {
        "x-message-ttl": ttl,
        "x-dead-letter-exchange": EXCHANGES.JOBS,
        "x-dead-letter-routing-key": queue,
      },
    });
    await channel.bindQueue(
      retryQueueName(queue, tier),
      EXCHANGES.RETRY,
      retryRoutingKey(queue, tier),
    );
  }
}

/**
 * Declares the whole broker topology (`BROKER_TOPOLOGY`): all exchanges, then every queue with its bindings, retry tiers
 * and dead-letter queue. Idempotent; call it at startup of every process that publishes or consumes. Redeclaring with the
 * same arguments is a no-op on the broker.
 * @param {import("amqplib").Channel} channel
 * @param {{ retryPolicy: { maxAttempts: number, baseDelayMs: number, maxDelayMs: number } }} options
 */
export async function declareBrokerTopology(channel, { retryPolicy }) {
  for (const { name, type } of BROKER_TOPOLOGY.exchanges)
    await channel.assertExchange(name, type, { durable: true });
  for (const entry of BROKER_TOPOLOGY.queues) await declareQueue(channel, entry, retryPolicy);
}
