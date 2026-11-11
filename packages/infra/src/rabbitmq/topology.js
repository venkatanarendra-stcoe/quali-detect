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
 * Declares exchanges, the main queue, retry tiers and the dead-letter queue (idempotent).
 * @param {import("amqplib").Channel} channel
 * @param {{ queue: string, retryPolicy: { maxAttempts: number, baseDelayMs: number, maxDelayMs: number } }} options
 */
export async function assertTopology(channel, { queue, retryPolicy }) {
  if (!QUEUE_NAME.test(queue)) throw new TypeError(`Invalid queue name "${queue}"`);
  for (const exchange of Object.values(EXCHANGES))
    await channel.assertExchange(exchange, "direct", { durable: true });

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
