import { useQuery } from "@tanstack/react-query";
import {
  MFA_PENDING,
  PLATFORM_ME_KEY,
  platformAuthService,
} from "../services/platform-auth-service.js";

/**
 * The signed-in platform user from `GET /platform/me` (TanStack Query owns it).
 * status: "loading" | "anonymous" | "mfa-required" | "authenticated" | "error".
 * The server withholds the profile until MFA is complete, so "authenticated" always means a verified session.
 */
export function usePlatformSession() {
  const query = useQuery({
    queryKey: PLATFORM_ME_KEY,
    queryFn: ({ signal }) => platformAuthService.me({ signal }),
    retry: false,
    staleTime: 60_000,
  });
  let status = "authenticated";
  if (query.isPending) status = "loading";
  else if (query.isError) status = "error";
  else if (query.data === null) status = "anonymous";
  else if (query.data === MFA_PENDING) status = "mfa-required";
  return {
    status,
    me: status === "authenticated" ? query.data : null,
    error: query.error,
    refetch: query.refetch,
  };
}
