import { useQuery } from "@tanstack/react-query";
import { authService, ME_KEY } from "../services/auth-service.js";

/**
 * The signed-in user from `GET /me` (TanStack Query owns it; nothing is mirrored into Zustand).
 * status: "loading" | "anonymous" | "authenticated" | "tenant-blocked" (active tenant suspended/deactivated) | "error".
 */
export function useSession() {
  const query = useQuery({
    queryKey: ME_KEY,
    queryFn: ({ signal }) => authService.me({ signal }),
    retry: false,
    staleTime: 60_000,
  });
  let status = "authenticated";
  if (query.isPending) status = "loading";
  else if (query.isError)
    status = query.error?.code === "TENANT_SUSPENDED" ? "tenant-blocked" : "error";
  else if (query.data === null) status = "anonymous";
  return { status, me: query.data ?? null, error: query.error, refetch: query.refetch };
}

/** The active tenant id; only call under `RequireTenant`. */
export function useTenantId() {
  const { me } = useSession();
  return me?.tenant?.id ?? null;
}
