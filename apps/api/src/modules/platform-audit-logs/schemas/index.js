import { z } from "zod";
import { auditCursorListResponseSchema, auditQuerySchema } from "../../../lib/audit-view.js";

export { auditCursorListResponseSchema as platformAuditLogListResponseSchema };

/** Platform audit log query: the common filters plus the affected tenant, with cursor pagination. */
export const listPlatformAuditLogsQuerySchema = auditQuerySchema(
  { tenantId: z.string().uuid().optional() },
  { cursor: true },
);
