import { createAuditService } from "../audit/audit-service.js";

/** Builds the immutable audit service. Requires the database. @param {{ infra: any, logger: import("pino").Logger }} deps */
export function createAudit({ infra, logger }) {
  if (!infra.db) throw new Error("The audit service requires DATABASE_URL.");
  return createAuditService({ db: infra.db, logger });
}
