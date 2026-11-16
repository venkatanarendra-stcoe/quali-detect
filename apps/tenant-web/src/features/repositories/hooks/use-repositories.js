import { keepPreviousData, useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useTenantId } from "@/features/auth/hooks/use-session.js";
import { usePageList } from "@/hooks/use-page-list.js";
import { integrationKeys } from "@/features/integrations/hooks/use-integrations.js";
import { repositoriesService } from "../services/repositories-service.js";

/** Keys start with the tenant (and carry the repository id), so nothing crosses tenants or repositories. */
export const repositoryKeys = {
  all: (tenantId) => ["tenant", tenantId, "repositories"],
  list: (tenantId, params) => ["tenant", tenantId, "repositories", "list", params],
  detail: (tenantId, id) => ["tenant", tenantId, "repositories", "detail", id],
  available: (tenantId, workspaceId, params) => [
    "tenant",
    tenantId,
    "repositories",
    "available",
    workspaceId,
    params,
  ],
  branches: (tenantId, id) => ["tenant", tenantId, "repositories", "branches", id],
  pulls: (tenantId, id) => ["tenant", tenantId, "repositories", "pulls", id],
};

/** Offset list for pickers that need the whole (small) set at once, e.g. a repository filter. */
export function useRepositoryList(params) {
  const tenantId = useTenantId();
  return useQuery({
    queryKey: repositoryKeys.list(tenantId, params),
    queryFn: ({ signal }) => repositoriesService.list(params, { signal }),
    placeholderData: keepPreviousData,
  });
}
/**
 * Numbered list of the Repositories page; `params` are the filters and sort, `paging` the URL page state of
 * `useListParams` (`page`, `pageSize`, `setPage`).
 */
export function useRepositoryPageList(params, paging) {
  const tenantId = useTenantId();
  return usePageList({
    queryKey: [...repositoryKeys.all(tenantId), "paged", params],
    fetchPage: ({ page, pageSize }, signal) =>
      repositoriesService.list({ ...params, page, pageSize }, { signal }),
    ...paging,
  });
}
export function useRepository(repositoryId) {
  const tenantId = useTenantId();
  return useQuery({
    queryKey: repositoryKeys.detail(tenantId, repositoryId),
    queryFn: ({ signal }) => repositoriesService.get(repositoryId, { signal }),
    enabled: Boolean(repositoryId),
  });
}
export function useAvailableRepositories(workspaceId, params, { enabled = true } = {}) {
  const tenantId = useTenantId();
  return useQuery({
    queryKey: repositoryKeys.available(tenantId, workspaceId, params),
    queryFn: ({ signal }) => repositoriesService.available(workspaceId, params, { signal }),
    enabled,
    placeholderData: keepPreviousData,
  });
}
export function useBranches(repositoryId, { enabled = true } = {}) {
  const tenantId = useTenantId();
  return useQuery({
    queryKey: repositoryKeys.branches(tenantId, repositoryId),
    queryFn: ({ signal }) => repositoriesService.branches(repositoryId, { signal }),
    enabled,
  });
}
export function usePullRequests(repositoryId, { enabled = true } = {}) {
  const tenantId = useTenantId();
  return useQuery({
    queryKey: repositoryKeys.pulls(tenantId, repositoryId),
    queryFn: ({ signal }) => repositoriesService.pullRequests(repositoryId, { signal }),
    enabled,
  });
}

function useRepositoryMutation(mutationFn) {
  const queryClient = useQueryClient();
  const tenantId = useTenantId();
  return useMutation({
    mutationFn,
    onSuccess: () =>
      Promise.all([
        queryClient.invalidateQueries({ queryKey: repositoryKeys.all(tenantId) }),
        queryClient.invalidateQueries({ queryKey: integrationKeys.installations(tenantId) }),
      ]),
  });
}
export const useConnectRepository = (workspaceId) =>
  useRepositoryMutation(({ body, idempotencyKey }) =>
    repositoriesService.connect(workspaceId, body, idempotencyKey),
  );
export const useUpdateRepository = (repositoryId) =>
  useRepositoryMutation((body) => repositoriesService.update(repositoryId, body));
export const useSyncRepository = () =>
  useRepositoryMutation((repositoryId) => repositoriesService.sync(repositoryId));
export const useEnableRepository = () =>
  useRepositoryMutation((repositoryId) => repositoriesService.enable(repositoryId));
export const useDisableRepository = () =>
  useRepositoryMutation((repositoryId) => repositoriesService.disable(repositoryId));
export const useDisconnectRepository = () =>
  useRepositoryMutation(({ repositoryId, confirm }) =>
    repositoriesService.disconnect(repositoryId, confirm),
  );
