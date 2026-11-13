/** A message the broker could not route to any queue (mandatory publish, `basic.return`). Always a FAILED publish. */
export class UnroutableMessageError extends Error {
  /** @param {{ exchange: string, routingKey: string, replyText?: string }} details */
  constructor({ exchange, routingKey, replyText }) {
    super(
      `Message was not routed to any queue (exchange "${exchange}", routing key "${routingKey}"${replyText ? `: ${replyText}` : ""})`,
    );
    this.name = "UnroutableMessageError";
    this.exchange = exchange;
    this.routingKey = routingKey;
  }
}

/** Per channel: publishes still waiting for their confirm. A `basic.return` is delivered BEFORE the matching ack. */
const pendingByChannel = new WeakMap();

function pendingOf(channel) {
  let pending = pendingByChannel.get(channel);
  if (!pending) {
    pending = new Set();
    pendingByChannel.set(channel, pending);
    channel.on("return", (returned) => {
      const entry = [...pending].find(
        (candidate) =>
          !candidate.returned &&
          candidate.exchange === returned.fields.exchange &&
          candidate.routingKey === returned.fields.routingKey,
      );
      if (entry) {
        entry.returned = true;
        entry.replyText = returned.fields.replyText;
      }
    });
  }
  return pending;
}

/**
 * Publishes on a CONFIRM channel with the `mandatory` flag and resolves only when the broker confirmed AND did not return
 * the message as unroutable. An unroutable message (no queue bound for the routing key) is rejected with
 * `UnroutableMessageError`: it is a failed publish, never a silent success (a bare confirm only says the broker took the
 * message, even when it then drops it). Callers (outbox relay, consumer retry/dead-letter copies) therefore retry or
 * redeliver instead of losing the message.
 * @param {import("amqplib").ConfirmChannel} channel
 * @param {string} exchange
 * @param {string} routingKey
 * @param {Buffer} content
 * @param {import("amqplib").Options.Publish} [options]
 * @returns {Promise<void>}
 */
export function publishConfirmed(channel, exchange, routingKey, content, options = {}) {
  const pending = pendingOf(channel);
  const entry = { exchange, routingKey, returned: false, replyText: undefined };
  pending.add(entry);
  return new Promise((resolve, reject) => {
    const settle = (error) => {
      pending.delete(entry);
      if (error) reject(error);
      else if (entry.returned)
        reject(new UnroutableMessageError({ exchange, routingKey, replyText: entry.replyText }));
      else resolve(undefined);
    };
    try {
      channel.publish(exchange, routingKey, content, { ...options, mandatory: true }, settle);
    } catch (error) {
      settle(error);
    }
  });
}
