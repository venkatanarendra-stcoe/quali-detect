import fp from "fastify-plugin";
import { createAuditService } from "../audit/audit-service.js";

/** Decorates `app.audit` (immutable audit service). Requires the database. */
export default fp(
  async function auditPlugin(app) {
    if (!app.infra.db) throw new Error("The audit service requires DATABASE_URL.");
    app.decorate("audit", createAuditService({ db: app.infra.db, logger: app.log }));
  },
  { name: "audit", dependencies: ["infrastructure"] },
);
