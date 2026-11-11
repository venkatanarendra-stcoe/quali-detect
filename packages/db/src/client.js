import { PrismaClient } from "@prisma/client";

/**
 * Creates a new Prisma client. Prefer `getDbClient()` in services and workers; use this only when a separate client
 * is really needed (scripts, isolated checks).
 * @param {ConstructorParameters<typeof PrismaClient>[0]} [options] e.g. `{ datasourceUrl }` to override DATABASE_URL.
 * @returns {PrismaClient}
 */
export function createDbClient(options) {
  return new PrismaClient(options);
}

const SINGLETON = Symbol.for("qmentisai.db.client");

/**
 * Process-wide Prisma client (one connection pool per process). The instance is stored on `globalThis`, so module
 * reloads in watch mode do not leak connection pools. Options only apply on first creation.
 * @param {ConstructorParameters<typeof PrismaClient>[0]} [options]
 * @returns {PrismaClient}
 */
export function getDbClient(options) {
  globalThis[SINGLETON] ??= createDbClient(options);
  return globalThis[SINGLETON];
}

/** Disconnects and forgets the singleton client (graceful shutdown). */
export async function disconnectDbClient() {
  const client = globalThis[SINGLETON];
  if (!client) return;
  delete globalThis[SINGLETON];
  await client.$disconnect();
}

/**
 * Connectivity check for readiness probes: resolves when the database answers `SELECT 1`.
 * @param {{ $queryRaw: Function }} client
 */
export async function pingDatabase(client) {
  await client.$queryRaw`SELECT 1`;
}
