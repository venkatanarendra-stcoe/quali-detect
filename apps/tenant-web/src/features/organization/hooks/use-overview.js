import { useQuery } from "@tanstack/react-query";
import { useTenantId } from "@/features/auth/hooks/use-session.js";
import { overviewService } from "../services/overview-service.js";

/** Overview data of the active tenant; the tenant id is part of the cache key. */
export function useOverview() {
  const tenantId = useTenantId();
  return useQuery({
    queryKey: ["overview", tenantId],
    queryFn: ({ signal }) => overviewService.get({ signal }),
  });
}
