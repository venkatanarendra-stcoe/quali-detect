export { auditCursorListResponseSchema as auditLogListResponseSchema } from "../../../lib/audit-view.js";
import { auditQuerySchema } from "../../../lib/audit-view.js";

/** Tenant audit log query. There is deliberately no tenant filter: the tenant is always the session's. */
export const listAuditLogsQuerySchema = auditQuerySchema({}, { cursor: true });
