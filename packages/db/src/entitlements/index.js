/**
 * Entitlements and quotas: Prisma-only data access and rules shared by the API and the workers (a worker cannot import
 * `apps/api`). Every function accepts an optional `client` (Prisma client or interactive-transaction client) so a caller
 * can consume quota atomically with its own writes.
 */
export * from "./keys.js";
export * from "./errors.js";
export * from "./repository.js";
export * from "./service.js";
