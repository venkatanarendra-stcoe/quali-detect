import { keepPreviousData, useQuery } from "@tanstack/react-query";
import { auditService } from "../services/audit-service.js";

export const auditKeys = { list: (params) => ["platform", "audit-logs", params] };

export function useAuditLogs(params) {
  return useQuery({
    queryKey: auditKeys.list(params),
    queryFn: ({ signal }) => auditService.list(params, { signal }),
    placeholderData: keepPreviousData,
  });
}
