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

/**
 * Changes a consent: `{ externalConsent }` (file names to an external provider) or `{ codeSnippetConsent }` (short code excerpts
 * of findings, ADR-013 addendum). The server answer replaces the cache (no optimistic write: it is a consent), so withdrawing the
 * first consent shows the second switched off exactly as the server stored it. Each change is audited by the server.
 */
export function useUpdateAiConsent() {
  const tenantId = useTenantId();
  const queryClient = useQueryClient();
  return useMutation({
    /** @param {{ externalConsent?: boolean, codeSnippetConsent?: boolean }} body */
    mutationFn: (body) => aiSettingsService.update(body),
    onSuccess: (stored, body) => {
      const before = queryClient.getQueryData(aiSettingsKey(tenantId));
      queryClient.setQueryData(aiSettingsKey(tenantId), stored);
      if ("codeSnippetConsent" in body)
        toast.success(
          stored.codeSnippetConsent
            ? "Short code excerpts may now be sent to the external provider."
            : "Code excerpts are no longer sent to the external provider.",
          { description: "The change is recorded in the audit log." },
        );
      else
        toast.success(
          stored.externalConsent
            ? "External AI providers are now allowed."
            : "External AI providers are no longer allowed.",
          {
            description:
              !stored.externalConsent && before?.codeSnippetConsent
                ? "Code excerpts were turned off too. The change is recorded in the audit log."
                : "The change is recorded in the audit log.",
          },
        );
    },
    onError: (error) =>
      toast.error("Could not save the setting.", { description: describeError(error) }),
  });
}
