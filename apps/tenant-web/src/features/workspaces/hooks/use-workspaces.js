import { keepPreviousData, useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { ME_KEY } from "@/features/auth/services/auth-service.js";
import { useTenantId } from "@/features/auth/hooks/use-session.js";
import { workspacesService } from "../services/workspaces-service.js";

/** Cache keys always start with the tenant and include the workspace id: nothing leaks across tenants or workspaces. */
export const workspaceKeys = {
  all: (tenantId) => ["tenant", tenantId, "workspaces"],
  list: (tenantId, params) => ["tenant", tenantId, "workspaces", "list", params],
  detail: (tenantId, workspaceId) => ["tenant", tenantId, "workspaces", workspaceId, "detail"],
  members: (tenantId, workspaceId, params) => [
    "tenant",
    tenantId,
    "workspaces",
    workspaceId,
    "members",
    params,
  ],
  assignments: (tenantId, workspaceId, params) => [
    "tenant",
    tenantId,
    "workspaces",
    workspaceId,
    "assignments",
    params,
  ],
};

export function useWorkspaceList(params) {
  const tenantId = useTenantId();
  return useQuery({
    queryKey: workspaceKeys.list(tenantId, params),
    queryFn: ({ signal }) => workspacesService.list(params, { signal }),
    placeholderData: keepPreviousData,
  });
}

export function useWorkspaceDetail(workspaceId) {
  const tenantId = useTenantId();
  return useQuery({
    queryKey: workspaceKeys.detail(tenantId, workspaceId),
    queryFn: ({ signal }) => workspacesService.get(workspaceId, { signal }),
    enabled: Boolean(workspaceId),
  });
}

export function useWorkspaceMembers(workspaceId, params) {
  const tenantId = useTenantId();
  return useQuery({
    queryKey: workspaceKeys.members(tenantId, workspaceId, params),
    queryFn: ({ signal }) => workspacesService.listMembers(workspaceId, params, { signal }),
    enabled: Boolean(workspaceId),
    placeholderData: keepPreviousData,
  });
}

/** Role assignments of the workspace (needs `workspace.view_roles`); pass `enabled: false` without it. */
export function useWorkspaceAssignments(workspaceId, params, { enabled = true } = {}) {
  const tenantId = useTenantId();
  return useQuery({
    queryKey: workspaceKeys.assignments(tenantId, workspaceId, params),
    queryFn: ({ signal }) => workspacesService.listAssignments(workspaceId, params, { signal }),
    enabled: enabled && Boolean(workspaceId),
    placeholderData: keepPreviousData,
  });
}

/**
 * Refreshes everything a workspace change can affect: workspace lists/details/members/assignments, and the session
 * (`/me`), because the workspace switcher, sidebar and navigation read the user's visible workspaces from it.
 */
export function useRefreshWorkspaces() {
  const queryClient = useQueryClient();
  const tenantId = useTenantId();
  return async () => {
    await Promise.all([
      queryClient.invalidateQueries({ queryKey: workspaceKeys.all(tenantId) }),
      queryClient.invalidateQueries({ queryKey: ["tenant", tenantId, "directory", "total"] }),
      queryClient.invalidateQueries({ queryKey: ME_KEY }),
    ]);
  };
}

/** A workspace mutation that refreshes dependent data on success. */
function useWorkspaceMutation(mutationFn) {
  const refresh = useRefreshWorkspaces();
  return useMutation({ mutationFn, onSuccess: refresh });
}

export const useCreateWorkspace = () =>
  useWorkspaceMutation((body) => workspacesService.create(body));
export const useUpdateWorkspace = (workspaceId) =>
  useWorkspaceMutation((body) => workspacesService.update(workspaceId, body));
export const useArchiveWorkspace = (workspaceId) =>
  useWorkspaceMutation(() => workspacesService.archive(workspaceId));
export const useRestoreWorkspace = (workspaceId) =>
  useWorkspaceMutation(() => workspacesService.restore(workspaceId));
export const useRemoveWorkspaceMember = (workspaceId) =>
  useWorkspaceMutation((userId) => workspacesService.removeMember(workspaceId, userId));
export const useCreateAssignment = (workspaceId) =>
  useWorkspaceMutation((body) => workspacesService.createAssignment(workspaceId, body));
export const useRevokeAssignment = (workspaceId) =>
  useWorkspaceMutation((assignmentId) =>
    workspacesService.revokeAssignment(workspaceId, assignmentId),
  );
