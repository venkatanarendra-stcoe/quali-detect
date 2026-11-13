import { useTenantId } from "@/features/auth/hooks/use-session.js";
import { useCursorList } from "@/hooks/use-cursor-list.js";
import { auditService } from "../services/audit-service.js";

/** Cache keys start with the tenant, so entries never leak across tenants. */
export const auditKeys = { list: (tenantId, params) => ["tenant", tenantId, "audit-logs", params] };

/** "Load more" audit list; `params` are the filters, sort and `limit` (never a cursor or page). */
export function useAuditLogs(params) {
  const tenantId = useTenantId();
  return useCursorList({
    queryKey: auditKeys.list(tenantId, params),
    fetchPage: (cursor, signal) => auditService.list({ ...params, cursor }, { signal }),
  });
}
