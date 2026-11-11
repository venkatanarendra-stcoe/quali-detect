/**
 * Operational check: verifies the configured PostgreSQL, Redis and RabbitMQ connections using the same .env values the
 * API uses. Prints PASS / FAIL / SKIPPED per service (never URLs or passwords) and exits 1 if a configured service fails.
 * Usage: pnpm --filter @qmentisai/api check:connections
 */
import { createDbClient, pingDatabase } from "@qmentisai/db";
import { buildCacheKey } from "@qmentisai/shared";
import { closeRedis, createRabbitConnection, createRedisClient, pingRedis } from "@qmentisai/infra";
import { ConfigError, loadConfig } from "../src/config/index.js";

let config;
try {
  config = loadConfig();
} catch (error) {
  if (!(error instanceof ConfigError)) throw error;
  console.error(error.message);
  process.exit(1);
}
const { databaseUrl, redisUrl, rabbitmqUrl } = config.infra;
const results = [];
const record = (service, status, detail = "") => {
  results.push({ service, status });
  console.log(`${status.padEnd(8)} ${service}${detail ? `: ${detail}` : ""}`);
};
const reason = (error) => {
  const line = String(error?.message ?? error)
    .split("\n")
    .map((part) => part.trim())
    .filter(Boolean)
    .pop();
  return `${(error?.errorCode ?? error?.code) ? `${error.errorCode ?? error.code} ` : ""}${line ?? "unknown error"}`.replace(
    /\/\/[^@\s]*@/g,
    "//***@",
  );
};

async function checkDatabase() {
  if (!databaseUrl) return record("postgresql", "SKIPPED", "DATABASE_URL is not set");
  const db = createDbClient({ datasourceUrl: databaseUrl });
  try {
    await pingDatabase(db);
    const [row] =
      await db.$queryRaw`SELECT current_database() AS name, current_setting('server_version') AS version`;
    record("postgresql", "PASS", `database "${row.name}", server ${row.version}`);
  } catch (error) {
    record("postgresql", "FAIL", reason(error));
  } finally {
    await db.$disconnect().catch(() => {});
  }
}

async function checkRedis() {
  if (!redisUrl) return record("redis", "SKIPPED", "REDIS_URL is not set");
  const redis = createRedisClient({ url: redisUrl, name: "qmentisai-check" });
  try {
    await pingRedis(redis);
    const key = buildCacheKey({
      tenantId: "connection-check",
      namespace: "check",
      id: String(process.pid),
    });
    await redis.set(key, "ok", "EX", 10);
    const value = await redis.get(key);
    await redis.del(key);
    if (value !== "ok") throw new Error("write/read round trip failed");
    record("redis", "PASS", "PING and write/read/delete round trip");
  } catch (error) {
    record("redis", "FAIL", reason(error));
  } finally {
    await closeRedis(redis);
  }
}

async function checkRabbitMq() {
  if (!rabbitmqUrl) return record("rabbitmq", "SKIPPED", "RABBITMQ_URL is not set");
  const connection = createRabbitConnection({ url: rabbitmqUrl, connectAttempts: 1 });
  try {
    const channel = await connection.createChannel();
    // Exclusive, auto-deleted queue: nothing is left behind on the broker.
    const { queue } = await channel.assertQueue("", { exclusive: true, autoDelete: true });
    channel.sendToQueue(queue, Buffer.from("ok"));
    let message = false;
    for (let i = 0; i < 20 && !message; i += 1) {
      message = await channel.get(queue, { noAck: true });
      if (!message) await new Promise((resolve) => setTimeout(resolve, 50));
    }
    if (!message || message.content.toString() !== "ok")
      throw new Error("publish/get round trip failed");
    await channel.close();
    record("rabbitmq", "PASS", "connected; temporary queue publish/get round trip");
  } catch (error) {
    record("rabbitmq", "FAIL", reason(error));
  } finally {
    await connection.close();
  }
}

await checkDatabase();
await checkRedis();
await checkRabbitMq();
process.exit(results.some((r) => r.status === "FAIL") ? 1 : 0);
