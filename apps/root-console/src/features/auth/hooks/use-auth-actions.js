import { useMutation, useQueryClient } from "@tanstack/react-query";
import { useNavigate } from "react-router";
import { PLATFORM_ME_KEY, platformAuthService } from "../services/platform-auth-service.js";
import { discardCacheKeepingSession, endSessionInCache } from "../services/session-cache.js";

/** Sign-in, MFA verification and sign-out. Any change of identity discards all cached platform data. */
export function useAuthActions() {
  const queryClient = useQueryClient();
  const navigate = useNavigate();
  const refreshSession = async () => {
    discardCacheKeepingSession(queryClient);
    await queryClient
      .fetchQuery({
        queryKey: PLATFORM_ME_KEY,
        queryFn: () => platformAuthService.me(),
        staleTime: 0,
      })
      .catch(() => {});
  };

  const login = useMutation({ mutationFn: platformAuthService.login, onSuccess: refreshSession });
  const verifyMfa = useMutation({
    mutationFn: platformAuthService.verifyMfa,
    onSuccess: refreshSession,
  });
  const logout = useMutation({
    mutationFn: platformAuthService.logout,
    onSettled: () => {
      endSessionInCache(queryClient);
      navigate("/login", { replace: true });
    },
  });
  return { login, verifyMfa, logout };
}
