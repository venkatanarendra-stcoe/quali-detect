import { useMutation, useQueryClient } from "@tanstack/react-query";
import { useNavigate } from "react-router";
import { authService, ME_KEY } from "../services/auth-service.js";
import { discardCacheKeepingSession, endSessionInCache } from "../services/session-cache.js";

/** Sign-in, sign-out and tenant switching. Any change of identity or tenant discards cached server data. */
export function useAuthActions() {
  const queryClient = useQueryClient();
  const navigate = useNavigate();

  const login = useMutation({
    mutationFn: authService.login,
    onSuccess: async () => {
      discardCacheKeepingSession(queryClient);
      await queryClient
        .fetchQuery({ queryKey: ME_KEY, queryFn: () => authService.me(), staleTime: 0 })
        .catch(() => {});
    },
  });

  const logout = useMutation({
    mutationFn: authService.logout,
    onSettled: () => {
      endSessionInCache(queryClient);
      navigate("/login", { replace: true });
    },
  });

  const switchTenant = useMutation({
    mutationFn: authService.switchTenant,
    onSuccess: async () => {
      // Nothing from the previous tenant may remain in the cache.
      discardCacheKeepingSession(queryClient);
      await queryClient
        .fetchQuery({ queryKey: ME_KEY, queryFn: () => authService.me(), staleTime: 0 })
        .catch(() => {});
      navigate("/", { replace: true });
    },
  });

  const acceptInvitation = useMutation({
    mutationFn: authService.acceptInvitation,
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ["account"] }),
  });

  return { login, logout, switchTenant, acceptInvitation };
}
