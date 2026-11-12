import { keepPreviousData, useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { usePermissions } from "@/features/authorization/hooks/use-permissions.js";
import { can } from "@qmentisai/shared";
import { useTenantId } from "@/features/auth/hooks/use-session.js";
import { integrationsService } from "../services/integrations-service.js";

/** Cache keys start with the tenant, so nothing leaks across tenants. */
export const integrationKeys = {
  all: (tenantId) => ["tenant", tenantId, "integrations"],
  catalog: (tenantId) => ["tenant", tenantId, "integrations", "catalog"],
  settings: (tenantId) => ["tenant", tenantId, "integrations", "settings"],
  installations: (tenantId) => ["tenant", tenantId, "integrations", "installations"],
  workspace: (tenantId, workspaceId) => [
    "tenant",
    tenantId,
    "integrations",
    "workspace",
    workspaceId,
  ],
  allowList: (tenantId, workspaceId, linkId, params) => [
    "tenant",
    tenantId,
    "integrations",
    "workspace",
    workspaceId,
    "allow-list",
    linkId,
    params,
  ],
  deliveries: (tenantId, installationId, params) => [
    "tenant",
    tenantId,
    "integrations",
    "deliveries",
    installationId,
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
export function useIntegrationSettings() {
  const tenantId = useTenantId();
  return useQuery({
    queryKey: integrationKeys.settings(tenantId),
    queryFn: ({ signal }) => integrationsService.settings({ signal }),
  });
}
/** Installations of the organization (read-only, integration.view) with the workspaces using each. */
export function useInstallations() {
  const tenantId = useTenantId();
  return useQuery({
    queryKey: integrationKeys.installations(tenantId),
    queryFn: ({ signal }) => integrationsService.installations({ signal }),
    select: (data) => data.items,
  });
}
/** This workspace's links plus `configured` and `linkingEnabled` (workspace_integration.view). */
export function useWorkspaceIntegrations(workspaceId, options = {}) {
  const tenantId = useTenantId();
  return useQuery({
    queryKey: integrationKeys.workspace(tenantId, workspaceId),
    queryFn: ({ signal }) => integrationsService.workspaceOverview(workspaceId, { signal }),
    ...options,
  });
}
/** Linked accounts of the workspace (what the Connect repository wizard offers). */
export const useWorkspaceLinks = (workspaceId) =>
  useWorkspaceIntegrations(workspaceId, {
    select: (data) => data.items.filter((l) => l.status === "linked"),
  });
export function useDeliveries(installationId, params) {
  const tenantId = useTenantId();
  return useQuery({
    queryKey: integrationKeys.deliveries(tenantId, installationId, params),
    queryFn: ({ signal }) => integrationsService.deliveries(installationId, params, { signal }),
    enabled: Boolean(installationId),
    placeholderData: keepPreviousData,
  });
}
export function useAllowList(workspaceId, linkId, params) {
  const tenantId = useTenantId();
  return useQuery({
    queryKey: integrationKeys.allowList(tenantId, workspaceId, linkId, params),
    queryFn: ({ signal }) => integrationsService.allowList(workspaceId, linkId, params, { signal }),
    placeholderData: keepPreviousData,
  });
}

function useIntegrationMutation(mutationFn, { alsoRepositories = false } = {}) {
  const queryClient = useQueryClient();
  const tenantId = useTenantId();
  return useMutation({
    mutationFn,
    onSuccess: () =>
      Promise.all([
        queryClient.invalidateQueries({ queryKey: integrationKeys.all(tenantId) }),
        alsoRepositories
          ? queryClient.invalidateQueries({ queryKey: ["tenant", tenantId, "repositories"] })
          : null,
      ]),
  });
}
export const useUpdateSettings = () =>
  useIntegrationMutation((allowWorkspaceLinking) =>
    integrationsService.updateSettings(allowWorkspaceLinking),
  );
export const useStartLinking = () =>
  useMutation({ mutationFn: (workspaceId) => integrationsService.start(workspaceId) });
export const useDiscoverInstallations = () =>
  useMutation({ mutationFn: (workspaceId) => integrationsService.discover(workspaceId) });
export const useAuthorizeInstallation = () =>
  useMutation({
    mutationFn: ({ workspaceId, installationId }) =>
      integrationsService.authorize(workspaceId, installationId),
  });
export const useLinkAccount = () =>
  useIntegrationMutation((body) => integrationsService.link(body));
export const useRefreshLink = (workspaceId) =>
  useIntegrationMutation((linkId) => integrationsService.refresh(workspaceId, linkId));
export const useSaveAllowList = (workspaceId) =>
  useIntegrationMutation(
    ({ linkId, body }) => integrationsService.saveAllowList(workspaceId, linkId, body),
    {
      alsoRepositories: true,
    },
  );
export const useUnlinkWorkspaceLink = (workspaceId) =>
  useIntegrationMutation(
    ({ linkId, confirm }) => integrationsService.unlink(workspaceId, linkId, confirm),
    {
      alsoRepositories: true,
    },
  );

/** Workspaces where the signed-in user may link source control (`workspace_integration.manage`). */
export function useManageableWorkspaces() {
  const permissions = usePermissions();
  return permissions.workspaces.filter((w) =>
    can(permissions, "workspace_integration.manage", { type: "workspace", workspaceId: w.id }),
  );
}
