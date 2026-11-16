import {
  keepPreviousData,
  useMutation,
  useQueries,
  useQuery,
  useQueryClient,
} from "@tanstack/react-query";
import { useTenantId } from "@/features/auth/hooks/use-session.js";
import { usePageList } from "@/hooks/use-page-list.js";
import { repositoryKeys } from "@/features/repositories/hooks/use-repositories.js";
import { pipelinesService } from "../services/pipelines-service.js";

/** Keys start with the tenant (then the workspace or pipeline id), so nothing crosses tenants or workspaces. */
export const pipelineKeys = {
  all: (tenantId) => ["tenant", tenantId, "pipelines"],
  list: (tenantId, workspaceId, params) => [
    "tenant",
    tenantId,
    "pipelines",
    "list",
    workspaceId,
    params,
  ],
  forRepository: (tenantId, repositoryId, params) => [
    "tenant",
    tenantId,
    "pipelines",
    "repository",
    repositoryId,
    params,
  ],
  options: (tenantId, workspaceId) => ["tenant", tenantId, "pipelines", "options", workspaceId],
  detail: (tenantId, id) => ["tenant", tenantId, "pipelines", "detail", id],
  versions: (tenantId, id, params) => ["tenant", tenantId, "pipelines", "versions", id, params],
  version: (tenantId, id, version) => ["tenant", tenantId, "pipelines", "version", id, version],
  executions: (tenantId, id, params) => ["tenant", tenantId, "pipelines", "executions", id, params],
  decisions: (tenantId, id, params) => ["tenant", tenantId, "pipelines", "decisions", id, params],
};

/** Numbered list of the Pipelines page; `params` are the filters and sort, `paging` the URL page state of `useListParams`. */
export function usePipelineList(workspaceId, params, paging) {
  const tenantId = useTenantId();
  return usePageList({
    queryKey: pipelineKeys.list(tenantId, workspaceId, params),
    fetchPage: ({ page, pageSize }, signal) =>
      pipelinesService.list({ workspaceId, ...params, page, pageSize }, { signal }),
    ...paging,
  });
}
/** Numbered list of a repository's pipelines (T-24 tab). */
export function useRepositoryPipelines(repositoryId, params, paging) {
  const tenantId = useTenantId();
  return usePageList({
    queryKey: pipelineKeys.forRepository(tenantId, repositoryId, params),
    fetchPage: ({ page, pageSize }, signal) =>
      pipelinesService.listForRepository(repositoryId, { ...params, page, pageSize }, { signal }),
    ...paging,
  });
}
export function usePipelineOptions(workspaceId, { enabled = true } = {}) {
  const tenantId = useTenantId();
  return useQuery({
    queryKey: pipelineKeys.options(tenantId, workspaceId),
    queryFn: ({ signal }) => pipelinesService.options(workspaceId, { signal }),
    enabled,
    staleTime: 60_000,
  });
}
export function usePipeline(pipelineId, { enabled = true } = {}) {
  const tenantId = useTenantId();
  return useQuery({
    queryKey: pipelineKeys.detail(tenantId, pipelineId),
    queryFn: ({ signal }) => pipelinesService.get(pipelineId, { signal }),
    enabled: enabled && Boolean(pipelineId),
  });
}
export function usePipelineVersions(pipelineId, params, { enabled = true } = {}) {
  const tenantId = useTenantId();
  return useQuery({
    queryKey: pipelineKeys.versions(tenantId, pipelineId, params),
    queryFn: ({ signal }) => pipelinesService.versions(pipelineId, params, { signal }),
    enabled,
    placeholderData: keepPreviousData,
  });
}
export function usePipelineVersion(pipelineId, version, { enabled = true } = {}) {
  const tenantId = useTenantId();
  return useQuery({
    queryKey: pipelineKeys.version(tenantId, pipelineId, version),
    queryFn: ({ signal }) => pipelinesService.version(pipelineId, version, { signal }),
    enabled: enabled && Boolean(version),
    staleTime: Infinity, // versions are immutable
  });
}
export function usePipelineExecutions(pipelineId, params, { enabled = true } = {}) {
  const tenantId = useTenantId();
  return useQuery({
    queryKey: pipelineKeys.executions(tenantId, pipelineId, params),
    queryFn: ({ signal }) => pipelinesService.executions(pipelineId, params, { signal }),
    enabled,
    placeholderData: keepPreviousData,
  });
}
export function useTriggerDecisions(pipelineId, params, { enabled = true } = {}) {
  const tenantId = useTenantId();
  return useQuery({
    queryKey: pipelineKeys.decisions(tenantId, pipelineId, params),
    queryFn: ({ signal }) => pipelinesService.decisions(pipelineId, params, { signal }),
    enabled,
    placeholderData: keepPreviousData,
  });
}

function usePipelineMutation(mutationFn, { alsoRepositories = false } = {}) {
  const queryClient = useQueryClient();
  const tenantId = useTenantId();
  return useMutation({
    mutationFn,
    onSuccess: () =>
      Promise.all([
        queryClient.invalidateQueries({ queryKey: pipelineKeys.all(tenantId) }),
        // the repository DTO carries pipelineCount
        alsoRepositories
          ? queryClient.invalidateQueries({ queryKey: repositoryKeys.all(tenantId) })
          : null,
      ]),
  });
}
export const useCreatePipeline = () =>
  usePipelineMutation(
    ({ repositoryId, body, idempotencyKey }) =>
      pipelinesService.create(repositoryId, body, idempotencyKey),
    { alsoRepositories: true },
  );
export const usePublishConfig = () =>
  usePipelineMutation(({ pipelineId, body, idempotencyKey }) =>
    pipelinesService.publishConfig(pipelineId, body, idempotencyKey),
  );
export const useUpdatePipeline = () =>
  usePipelineMutation(({ pipelineId, body }) => pipelinesService.update(pipelineId, body));
export const useSetPipelineEnabled = () =>
  usePipelineMutation(({ pipelineId, enabled }) =>
    enabled ? pipelinesService.enable(pipelineId) : pipelinesService.disable(pipelineId),
  );
export const useDeletePipeline = () =>
  usePipelineMutation(({ pipelineId, confirm }) => pipelinesService.remove(pipelineId, confirm), {
    alsoRepositories: true,
  });
/** Manual run: the dialog owns the Idempotency-Key and passes it, so a retry of the same attempt reuses it. */
export const useRunPipeline = () =>
  usePipelineMutation(({ pipelineId, body, idempotencyKey }) =>
    pipelinesService.run(pipelineId, body, idempotencyKey),
  );
export const useDryRun = () =>
  useMutation({
    mutationFn: ({ repositoryId, body }) => pipelinesService.dryRun(repositoryId, body),
  });

/**
 * Current configuration of each listed pipeline, for the trigger and scan chips: the list DTO carries trigger keys and types
 * but not the configuration. Versions are immutable, so each fetch is cached forever by (pipeline, version); rows render
 * their basic chips first. Returns `Map<pipelineId, config>`.
 * @param {Array<{ id: string, currentVersion: { version: number } | null }>} pipelines
 */
export function usePipelineConfigs(pipelines) {
  const tenantId = useTenantId();
  const results = useQueries({
    queries: pipelines.map((p) => ({
      queryKey: pipelineKeys.version(tenantId, p.id, p.currentVersion?.version),
      queryFn: ({ signal }) => pipelinesService.version(p.id, p.currentVersion.version, { signal }),
      enabled: Boolean(p.currentVersion),
      staleTime: Infinity,
      retry: false,
    })),
  });
  const map = new Map();
  pipelines.forEach((p, i) => {
    if (results[i]?.data?.config) map.set(p.id, results[i].data.config);
  });
  return map;
}
