import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { toast } from "sonner";
import { describeError } from "@/lib/api/index.js";
import { PREFERENCES_KEY, preferencesService } from "../services/preferences-service.js";

/**
 * The signed-in user's preferences (TanStack Query owns them).
 * @param {{ enabled?: boolean }} [options]
 */
export function usePreferences({ enabled = true } = {}) {
  return useQuery({
    queryKey: PREFERENCES_KEY,
    queryFn: ({ signal }) => preferencesService.get({ signal }),
    enabled,
    staleTime: 5 * 60_000,
  });
}

/**
 * Post-login landing from `GET /me/landing` (use-time decision on the server). Always refetched when the landing mounts, so a
 * stale default or a revoked workspace is never acted on from a cache; the tenant id is part of the key.
 * @param {string | null} tenantId
 */
export function useLanding(tenantId) {
  return useQuery({
    queryKey: ["account", "landing", tenantId],
    queryFn: ({ signal }) => preferencesService.landing({ signal }),
    staleTime: 0,
    gcTime: 0,
    retry: false,
  });
}

/**
 * Saves preferences with an optimistic cache update (the accent applies instantly through the provider), a toast, and a
 * rollback to the previous value on failure.
 * @param {{ successMessage?: string }} [options]
 */
export function useUpdatePreferences({ successMessage = "Preferences saved." } = {}) {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (patch) => preferencesService.update(patch),
    onMutate: async (patch) => {
      await queryClient.cancelQueries({ queryKey: PREFERENCES_KEY });
      const previous = queryClient.getQueryData(PREFERENCES_KEY);
      queryClient.setQueryData(PREFERENCES_KEY, (current) => ({ ...current, ...patch }));
      return { previous };
    },
    onError: (error, _patch, context) => {
      queryClient.setQueryData(PREFERENCES_KEY, context?.previous);
      toast.error("Could not save your preferences.", { description: describeError(error) });
    },
    onSuccess: (stored) => {
      queryClient.setQueryData(PREFERENCES_KEY, stored);
      toast.success(successMessage);
    },
  });
}
