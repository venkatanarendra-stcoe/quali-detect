import { EventEmitter } from "node:events";
import { randomBytes } from "node:crypto";
import {
  PIPELINE_TRIGGERS_BINDINGS,
  QUEUE_NAMES,
  SCM_EVENTS_EXCHANGE,
  createEventEnvelope,
  createJobEnvelope,
} from "@qmentisai/contracts";
import { createOutboxRepository } from "@qmentisai/db";
import {
  BROKER_TOPOLOGY,
  UnroutableMessageError,
  createConsumer,
  createOutbox,
  createOutboxRelay,
  createPublisher,
  declareBrokerTopology,
  deadLetterQueueName,
  mainQueueName,
  publishConfirmed,
  resolveRetryPolicy,
} from "@qmentisai/infra";

/**
 * Broker topology and publish safety (SPEC repositories-github §16.3 item 6, ADR-011): the shared topology definition and the
 * mandatory-publish rule. The REAL publisher, relay, consumer and outbox repository run IN PROCESS (the repository against the
 * disposable database) against `FakeBroker`, a channel double that models what matters here: exchanges, queues, bindings
 * (direct and topic routing), publisher confirms and `basic.return` for a mandatory publish nobody can route. No real RabbitMQ
 * is touched, so the owner's broker is never altered.
 */

const rand = (n = 4) => randomBytes(n).toString("hex");
const quiet = {
  info() {},
  warn() {},
  error() {},
  debug() {},
  child() {
    return quiet;
  },
};

const topicMatch = (pattern, key) => {
  const p = pattern.split(".");
  const k = key.split(".");
  const walk = (i, j) => {
    if (i === p.length) return j === k.length;
    if (p[i] === "#") return walk(i + 1, j) || (j < k.length && walk(i, j + 1));
    if (j === k.length) return false;
    return (p[i] === "*" || p[i] === k[j]) && walk(i + 1, j + 1);
  };
  return walk(0, 0);
};

/** An in-memory broker with the confirm/return semantics of RabbitMQ (mandatory flag, `basic.return` before the ack). */
export function createFakeBroker() {
  const state = { exchanges: new Map(), queues: new Map(), bindings: [] };
  const route = (exchange, key) => {
    const type = state.exchanges.get(exchange);
    return state.bindings
      .filter(
        (b) =>
          b.exchange === exchange && (type === "topic" ? topicMatch(b.key, key) : b.key === key),
      )
      .map((b) => b.queue);
  };
  const channel = () => {
    const ch = new EventEmitter();
    Object.assign(ch, {
      async assertExchange(name, type) {
        const have = state.exchanges.get(name);
        if (have && have !== type) throw new Error(`PRECONDITION_FAILED exchange ${name}`);
        state.exchanges.set(name, type);
      },
      async assertQueue(name, options = {}) {
        const have = state.queues.get(name);
        const args = JSON.stringify(options.arguments ?? {});
        if (have && have.args !== args) throw new Error(`PRECONDITION_FAILED queue ${name}`);
        if (!have) state.queues.set(name, { args, messages: [] });
        return { queue: name };
      },
      async bindQueue(queue, exchange, key) {
        if (!state.queues.has(queue) || !state.exchanges.has(exchange))
          throw new Error(`NOT_FOUND binding ${queue} <- ${exchange}`);
        if (
          !state.bindings.some((b) => b.queue === queue && b.exchange === exchange && b.key === key)
        )
          state.bindings.push({ queue, exchange, key });
      },
      async prefetch() {},
      async consume() {
        return { consumerTag: "fake" };
      },
      publish(exchange, key, content, options, callback) {
        queueMicrotask(() => {
          if (!state.exchanges.has(exchange))
            return callback(new Error(`NOT_FOUND exchange ${exchange}`));
          const targets = route(exchange, key);
          for (const q of targets)
            state.queues.get(q).messages.push({ exchange, key, content, options });
          if (targets.length === 0 && options?.mandatory)
            ch.emit("return", {
              fields: { exchange, routingKey: key, replyCode: 312, replyText: "NO_ROUTE" },
              properties: options,
              content,
            });
          callback(null); // the confirm: it arrives for a returned message too, AFTER the return
        });
        return true;
      },
      async cancel() {},
      async close() {
        ch.emit("close");
      },
    });
    return ch;
  };
  return {
    state,
    connection: {
      createConfirmChannel: async () => channel(),
      createChannel: async () => channel(),
      onClose: () => () => {},
    },
    /** A broker that lost its queues and bindings (rebuilt, or an operator deleted them); the exchanges still exist. */
    wipe() {
      state.queues.clear();
      state.bindings.length = 0;
    },
    depth: (queue) => state.queues.get(queue)?.messages.length ?? 0,
    snapshot: () =>
      JSON.stringify({
        exchanges: [...state.exchanges].sort(),
        queues: [...state.queues].map(([n, q]) => [n, q.args]).sort(),
        bindings: state.bindings.map((b) => `${b.queue}|${b.exchange}|${b.key}`).sort(),
      }),
  };
}

export async function buildBrokerWorld(db) {
  return {
    db,
    repository: createOutboxRepository({ db }),
    outbox: createOutbox({ repository: createOutboxRepository({ db }) }),
  };
}

const jobMessage = () =>
  createJobEnvelope({
    type: "test.broker.topology",
    schemaVersion: 1,
    initiator: { type: "system", id: "suite" },
    payload: { n: rand() },
  });
const eventMessage = () =>
  createEventEnvelope({
    type: "scm.github.push",
    schemaVersion: 1,
    subject: { type: "repository", id: "r-suite" },
    initiator: { type: "system", id: "suite" },
    payload: { n: rand() },
  });

const policy = resolveRetryPolicy();

async function relayFor(world, broker) {
  const publisher = createPublisher({ connection: broker.connection, logger: quiet });
  const relay = createOutboxRelay({
    repository: world.repository,
    publisher,
    logger: quiet,
    baseDelayMs: 1000,
    maxDelayMs: 1000,
  });
  return { publisher, relay };
}

const rowOf = (db, messageId) => db.outboxMessage.findFirst({ where: { messageId } });
/** Only the suite's own rows may be due while a check runs: park all others far in the future first. */
async function parkOthers(db) {
  await db.outboxMessage.updateMany({
    where: { status: "pending" },
    data: { availableAt: new Date(Date.now() + 3_600_000) },
  });
}

export const BROKER_CHECKS = [
  {
    id: "BRK-001",
    name: "the outbox relay publishing into a fresh broker with no bindings (before any worker has declared anything) loses nothing: every unroutable row stays pending with a retry time and an error and nothing is marked sent; once the topology is declared the same rows are delivered exactly once, and a further relay run does not deliver them again",
    async run(w) {
      const problems = [];
      const broker = createFakeBroker();
      await parkOthers(w.db);
      const { publisher, relay } = await relayFor(w, broker);
      // the relay's publisher declares the topology on its first channel; an operator then wipes the broker (or it was
      // rebuilt): the channel is still open, nothing is bound, and the relay publishes into that.
      await publisher.declareTopology();
      broker.wipe();
      const job = jobMessage();
      const event = eventMessage();
      await w.db.$transaction(async (tx) => {
        await w.outbox.enqueue(tx, { queue: QUEUE_NAMES.SCM, message: job });
        await w.outbox.enqueue(tx, {
          queue: QUEUE_NAMES.SCM_EVENTS,
          exchange: SCM_EVENTS_EXCHANGE,
          routingKey: "scm.github.push",
          message: event,
        });
      });
      const first = await relay.runOnce();
      if (first.sent !== 0) problems.push(`unroutable run reported ${first.sent} sent`);
      for (const [label, id] of [
        ["job", job.messageId],
        ["event", event.messageId],
      ]) {
        const row = await rowOf(w.db, id);
        if (row.status === "sent" || row.sentAt)
          problems.push(`${label} row was marked sent although nothing could route it`);
        if (label === "job" && (row.status !== "pending" || row.attempts !== 1 || !row.lastError))
          problems.push(`job row not pending/retried with an error: ${row.status} ${row.attempts}`);
      }
      const queued = [...broker.state.queues.values()].reduce((n, q) => n + q.messages.length, 0);
      if (queued !== 0)
        problems.push(`${queued} message(s) sit in queues of a broker with no bindings`);
      // the topology is declared (what a starting worker does), the failed rows become due again
      const ch = await broker.connection.createConfirmChannel();
      await declareBrokerTopology(ch, { retryPolicy: policy });
      await w.db.outboxMessage.updateMany({
        where: { messageId: { in: [job.messageId, event.messageId] } },
        data: { availableAt: new Date(Date.now() - 1000) },
      });
      for (let i = 0; i < 3; i += 1) await relay.runOnce(); // extra runs must find nothing new
      for (const [queue, want] of [
        [mainQueueName(QUEUE_NAMES.SCM), 1],
        [mainQueueName(QUEUE_NAMES.SCM_EVENTS), 1],
        [mainQueueName(QUEUE_NAMES.PIPELINE_TRIGGERS), 1],
      ])
        if (broker.depth(queue) !== want)
          problems.push(
            `${queue} holds ${broker.depth(queue)} message(s), expected exactly ${want}`,
          );
      for (const id of [job.messageId, event.messageId]) {
        const row = await rowOf(w.db, id);
        if (row.status !== "sent") problems.push(`row ${row.queue} ended ${row.status}, not sent`);
      }
      await publisher.close();
      return problems;
    },
  },
  {
    id: "BRK-002",
    name: "an unroutable publish is never confirmed as success: the publisher, the raw confirmed publish and the consumer's retry/dead-letter copy all reject with an unroutable error when no queue is bound, while the same publish with the topology declared resolves (control) and a non-mandatory publish would have been silently dropped",
    async run() {
      const problems = [];
      const broker = createFakeBroker();
      const publisher = createPublisher({ connection: broker.connection, logger: quiet });
      await publisher.declareTopology();
      // a queue outside the catalogue has no binding on the jobs exchange
      let error = null;
      await publisher
        .publish({ queue: "not-a-declared-queue", envelope: jobMessage() })
        .catch((e) => (error = e));
      if (!(error instanceof UnroutableMessageError))
        problems.push(`publish to an unbound queue resolved or failed differently: ${error?.name}`);
      // a topic message nobody is bound for
      error = null;
      await publisher
        .publish({
          queue: QUEUE_NAMES.SCM_EVENTS,
          exchange: SCM_EVENTS_EXCHANGE,
          routingKey: "other.prefix.thing",
          envelope: eventMessage(),
        })
        .catch((e) => (error = e));
      if (!(error instanceof UnroutableMessageError))
        problems.push("a topic publish with no matching binding was confirmed");
      // raw confirmed publish, and what a non-mandatory publish would do (control for the double)
      const ch = await broker.connection.createConfirmChannel();
      error = null;
      await publishConfirmed(ch, "qmentis.jobs", "nobody", Buffer.from("x")).catch(
        (e) => (error = e),
      );
      if (!(error instanceof UnroutableMessageError))
        problems.push("raw confirmed publish was confirmed");
      const dropped = await new Promise((resolve) =>
        ch.publish("qmentis.jobs", "nobody", Buffer.from("x"), {}, (e) => resolve(e === null)),
      );
      if (!dropped)
        problems.push("control: the double should silently confirm a non-mandatory publish");
      // the consumer's retry / dead-letter copy: a broker without the retry or DLX bindings must fail the settle
      const consumerBroker = createFakeBroker();
      const consumer = createConsumer({
        connection: consumerBroker.connection,
        queue: QUEUE_NAMES.SCM,
        handler: async () => {},
        logger: quiet,
      });
      await consumer.start();
      const cch = await consumerBroker.connection.createConfirmChannel();
      consumerBroker.state.bindings.length = 0; // bindings lost while the consumer runs
      error = null;
      await publishConfirmed(cch, "qmentis.dlx", QUEUE_NAMES.SCM, Buffer.from("x")).catch(
        (e) => (error = e),
      );
      if (!(error instanceof UnroutableMessageError))
        problems.push("a dead-letter copy without a DLQ binding was confirmed");
      // control: declared topology routes
      await declareBrokerTopology(cch, { retryPolicy: policy });
      await publisher.close();
      const ok = createPublisher({ connection: consumerBroker.connection, logger: quiet });
      const sent = await ok
        .publish({ queue: QUEUE_NAMES.SCM, envelope: jobMessage() })
        .catch((e) => e);
      if (sent instanceof Error)
        problems.push(`control: a routable publish failed: ${sent.message}`);
      if (consumerBroker.depth(mainQueueName(QUEUE_NAMES.SCM)) !== 1)
        problems.push("control: the routable publish did not reach the queue");
      await ok.close();
      return problems;
    },
  },
  {
    id: "BRK-003",
    name: "the one topology definition declares every catalogued queue with its dead-letter queue, retry tiers and the SCM topic bindings (scm-events gets scm.github.#, pipeline-triggers only push and pull_request), the declaration is idempotent, and a redeclaration with different arguments is refused rather than silently accepted",
    async run() {
      const problems = [];
      const broker = createFakeBroker();
      const ch = await broker.connection.createConfirmChannel();
      await declareBrokerTopology(ch, { retryPolicy: policy });
      const once = broker.snapshot();
      await declareBrokerTopology(ch, { retryPolicy: policy });
      if (broker.snapshot() !== once) problems.push("declaring twice changed the broker state");
      for (const queue of Object.values(QUEUE_NAMES)) {
        for (const name of [mainQueueName(queue), deadLetterQueueName(queue)])
          if (!broker.state.queues.has(name)) problems.push(`queue ${name} is not declared`);
        for (let tier = 1; tier < policy.maxAttempts; tier += 1)
          if (!broker.state.queues.has(`qmentis.${queue}.retry.${tier}`))
            problems.push(`retry tier ${tier} of ${queue} is not declared`);
      }
      if (BROKER_TOPOLOGY.queues.length !== Object.keys(QUEUE_NAMES).length)
        problems.push("the topology does not cover the whole queue catalogue");
      const bound = (queue) =>
        broker.state.bindings
          .filter((b) => b.queue === mainQueueName(queue) && b.exchange === SCM_EVENTS_EXCHANGE)
          .map((b) => b.key)
          .sort();
      if (bound(QUEUE_NAMES.SCM_EVENTS).join() !== "scm.github.#")
        problems.push(`scm-events bindings: ${bound(QUEUE_NAMES.SCM_EVENTS)}`);
      const want = PIPELINE_TRIGGERS_BINDINGS.map((b) => b.routingKey)
        .sort()
        .join();
      if (bound(QUEUE_NAMES.PIPELINE_TRIGGERS).join() !== want)
        problems.push(`pipeline-triggers bindings: ${bound(QUEUE_NAMES.PIPELINE_TRIGGERS)}`);
      for (const queue of Object.values(QUEUE_NAMES))
        if (
          ![QUEUE_NAMES.SCM_EVENTS, QUEUE_NAMES.PIPELINE_TRIGGERS].includes(queue) &&
          bound(queue).length
        )
          problems.push(`${queue} has an SCM binding`);
      // routing: a push reaches both queues, an installation event only scm-events, the dead-letter path works
      const pub = async (key) => {
        const before = (q) => broker.depth(mainQueueName(q));
        const a = [before(QUEUE_NAMES.SCM_EVENTS), before(QUEUE_NAMES.PIPELINE_TRIGGERS)];
        await publishConfirmed(ch, SCM_EVENTS_EXCHANGE, key, Buffer.from("{}"));
        return [
          before(QUEUE_NAMES.SCM_EVENTS) - a[0],
          before(QUEUE_NAMES.PIPELINE_TRIGGERS) - a[1],
        ];
      };
      if ((await pub("scm.github.push")).join() !== "1,1")
        problems.push("push is not delivered once to both queues");
      if ((await pub("scm.github.installation")).join() !== "1,0")
        problems.push("installation event reached the trigger router or not scm-events");
      await publishConfirmed(ch, "qmentis.dlx", QUEUE_NAMES.SCAN, Buffer.from("{}"));
      if (broker.depth(deadLetterQueueName(QUEUE_NAMES.SCAN)) !== 1)
        problems.push("dead-letter routing is broken");
      // incompatible redeclaration is refused (the owner's broker would refuse it too)
      let refused = false;
      await declareBrokerTopology(ch, {
        retryPolicy: resolveRetryPolicy({ baseDelayMs: 7, maxDelayMs: 7 }),
      }).catch(() => (refused = true));
      if (!refused) problems.push("a redeclaration with different retry arguments was accepted");
      return problems;
    },
  },
  {
    id: "BRK-004",
    name: "every process that touches the broker declares the same full topology at startup, with no per-process declarations: the API publisher, the outbox relay and a worker consumer each turn an empty broker into an identical one",
    async run() {
      const problems = [];
      const snapshots = {};
      {
        const b = createFakeBroker();
        const p = createPublisher({ connection: b.connection, logger: quiet });
        await p.declareTopology();
        snapshots.api = b.snapshot();
        await p.close();
      }
      {
        const b = createFakeBroker();
        const p = createPublisher({ connection: b.connection, logger: quiet });
        const relay = createOutboxRelay({
          repository: { processBatch: async () => ({ claimed: 0, sent: 0, failed: 0, dead: 0 }) },
          publisher: p,
          logger: quiet,
          pollIntervalMs: 5,
        });
        relay.start();
        for (let i = 0; i < 100 && b.state.queues.size === 0; i += 1)
          await new Promise((r) => setTimeout(r, 10));
        await relay.stop();
        snapshots.relay = b.snapshot();
        await p.close();
      }
      for (const queue of [QUEUE_NAMES.SCM, QUEUE_NAMES.PIPELINE_TRIGGERS, QUEUE_NAMES.SCAN]) {
        const b = createFakeBroker();
        const c = createConsumer({
          connection: b.connection,
          queue,
          handler: async () => {},
          logger: quiet,
        });
        await c.start();
        snapshots[`worker:${queue}`] = b.snapshot();
        await c.stop({ timeoutMs: 100 });
      }
      {
        // a publisher that was never asked to declare still declares before its first publish (lazy, once per channel)
        const b = createFakeBroker();
        const p = createPublisher({ connection: b.connection, logger: quiet });
        const sent = await p
          .publish({ queue: QUEUE_NAMES.SCM, envelope: jobMessage() })
          .catch((e) => e);
        if (sent instanceof Error || b.depth(mainQueueName(QUEUE_NAMES.SCM)) !== 1)
          problems.push("a first publish on an empty broker was not routed to its queue");
        await p.close();
      }
      const reference = snapshots.api;
      if (!reference || JSON.parse(reference).queues.length === 0)
        problems.push("the API publisher declared nothing at startup");
      for (const [who, snap] of Object.entries(snapshots))
        if (snap !== reference) problems.push(`${who} declared a different topology than the API`);
      return problems;
    },
  },
];
