import { keepPreviousData, useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useTenantId } from "@/features/auth/hooks/use-session.js";
import { integrationsService } from "../services/integrations-service.js";

/** Cache keys start with the tenant, so nothing leaks across tenants. */
export const integrationKeys = {
  all: (tenantId) => ["tenant", tenantId, "integrations"],
  catalog: (tenantId) => ["tenant", tenantId, "integrations", "catalog"],
  installations: (tenantId) => ["tenant", tenantId, "integrations", "installations"],
  deliveries: (tenantId, linkId, params) => [
    "tenant",
    tenantId,
    "integrations",
    "deliveries",
    linkId,
    params,
  ],
};

export function useCatalog() {
  const tenantId = useTenantId();
  return useQuery({
    queryKey: integrationKeys.catalog(tenantId),
    queryFn: ({ signal }) => integrationsService.catalog({ signal }),
  });
}
export function useInstallations({ enabled = true } = {}) {
  const tenantId = useTenantId();
  return useQuery({
    queryKey: integrationKeys.installations(tenantId),
    queryFn: ({ signal }) => integrationsService.installations({ signal }),
    enabled,
    select: (data) => data.items,
  });
}
export function useDeliveries(linkId, params) {
  const tenantId = useTenantId();
  return useQuery({
    queryKey: integrationKeys.deliveries(tenantId, linkId, params),
    queryFn: ({ signal }) => integrationsService.deliveries(linkId, params, { signal }),
    enabled: Boolean(linkId),
    placeholderData: keepPreviousData,
  });
}

function useIntegrationMutation(mutationFn) {
  const queryClient = useQueryClient();
  const tenantId = useTenantId();
  return useMutation({
    mutationFn,
    onSuccess: () => queryClient.invalidateQueries({ queryKey: integrationKeys.all(tenantId) }),
  });
}
export const useStartLinking = () => useMutation({ mutationFn: () => integrationsService.start() });
export const useAuthorizeInstallation = () =>
  useMutation({ mutationFn: (installationId) => integrationsService.authorize(installationId) });
export const useLinkInstallation = () =>
  useIntegrationMutation((body) => integrationsService.link(body));
export const useRefreshInstallation = () =>
  useIntegrationMutation((linkId) => integrationsService.refresh(linkId));
export const useSetScope = () =>
  useIntegrationMutation(({ linkId, workspaceIds }) =>
    integrationsService.setScope(linkId, workspaceIds),
  );
export const useUnlinkInstallation = () => {
  const queryClient = useQueryClient();
  const tenantId = useTenantId();
  return useMutation({
    mutationFn: ({ linkId, confirm }) => integrationsService.unlink(linkId, confirm),
    // Unlinking disconnects repositories, so repository lists change too.
    onSuccess: () =>
      Promise.all([
        queryClient.invalidateQueries({ queryKey: integrationKeys.all(tenantId) }),
        queryClient.invalidateQueries({ queryKey: ["tenant", tenantId, "repositories"] }),
      ]),
  });
};
