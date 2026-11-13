import { useCursorList } from "@/hooks/use-cursor-list.js";
import { auditService } from "../services/audit-service.js";

export const auditKeys = { list: (params) => ["platform", "audit-logs", params] };

/** "Load more" platform audit list; `params` are the filters, sort and `limit` (never a cursor or page). */
export function useAuditLogs(params) {
  return useCursorList({
    queryKey: auditKeys.list(params),
    fetchPage: (cursor, signal) => auditService.list({ ...params, cursor }, { signal }),
  });
}
