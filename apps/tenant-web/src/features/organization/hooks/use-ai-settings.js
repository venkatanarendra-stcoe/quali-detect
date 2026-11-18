import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { toast } from "sonner";
import { useTenantId } from "@/features/auth/hooks/use-session.js";
import { describeError } from "@/lib/api/index.js";
import { aiSettingsService } from "../services/ai-settings-service.js";

/** The tenant id is part of the key: nothing crosses tenants. */
export const aiSettingsKey = (tenantId) => ["tenant", tenantId, "settings", "ai"];

/** @param {{ enabled?: boolean }} [options] `enabled` is false without `tenant_settings.view` (no request is made) */
export function useAiSettings({ enabled = true } = {}) {
  const tenantId = useTenantId();
  return useQuery({
    queryKey: aiSettingsKey(tenantId),
    queryFn: ({ signal }) => aiSettingsService.get({ signal }),
    enabled,
  });
}

/** Turns the external-provider consent on or off. The server answer replaces the cache (no optimistic write: it is a consent). */
export function useUpdateAiConsent() {
  const tenantId = useTenantId();
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (externalConsent) => aiSettingsService.update(externalConsent),
    onSuccess: (stored) => {
      queryClient.setQueryData(aiSettingsKey(tenantId), stored);
      toast.success(
        stored.externalConsent
          ? "External AI providers are now allowed."
          : "External AI providers are no longer allowed.",
      );
    },
    onError: (error) =>
      toast.error("Could not save the setting.", { description: describeError(error) }),
  });
}
