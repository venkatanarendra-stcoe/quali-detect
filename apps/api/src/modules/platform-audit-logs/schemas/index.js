import { z } from "zod";
import { auditQuerySchema } from "../../../lib/audit-view.js";

export { auditListResponseSchema as platformAuditLogListResponseSchema } from "../../../lib/audit-view.js";

/** Platform audit log query: the common filters plus the affected tenant. */
export const listPlatformAuditLogsQuerySchema = auditQuerySchema({
  tenantId: z.string().uuid().optional(),
});
