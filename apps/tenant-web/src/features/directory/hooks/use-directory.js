import { keepPreviousData, useQuery } from "@tanstack/react-query";
import { useTenantId } from "@/features/auth/hooks/use-session.js";
import { directoryService } from "../services/directory-service.js";

const key = (tenantId, ...parts) => ["tenant", tenantId, "directory", ...parts];

/** Active members matching `q` (needs `user.view`). */
export function useUserSearch(q, { enabled = true } = {}) {
  const tenantId = useTenantId();
  return useQuery({
    queryKey: key(tenantId, "users", q),
    queryFn: ({ signal }) =>
      directoryService.users(
        { q: q || undefined, status: "active", pageSize: 20, sort: "name:asc" },
        { signal },
      ),
    enabled,
    placeholderData: keepPreviousData,
    select: (page) => page.items,
  });
}

/** Groups matching `q` (needs `group.view`). */
export function useGroupSearch(q, { enabled = true } = {}) {
  const tenantId = useTenantId();
  return useQuery({
    queryKey: key(tenantId, "groups", q),
    queryFn: ({ signal }) =>
      directoryService.groups({ q: q || undefined, pageSize: 20, sort: "name:asc" }, { signal }),
    enabled,
    placeholderData: keepPreviousData,
    select: (page) => page.items,
  });
}

/** Roles that can be assigned inside a workspace: those with at least one workspace-scope permission (needs `role.view`). */
export function useAssignableRoles({ enabled = true } = {}) {
  const tenantId = useTenantId();
  return useQuery({
    queryKey: key(tenantId, "roles", "assignable"),
    queryFn: ({ signal }) =>
      directoryService.roles({ pageSize: 100, sort: "name:asc" }, { signal }),
    enabled,
    staleTime: 60_000,
    select: (page) => page.items.filter((role) => role.workspacePermissions.length > 0),
  });
}

/** Tenant-wide counts for the overview tiles (each needs its own permission, hence `enabled`). */
export function useTotal(resource, params, { enabled }) {
  const tenantId = useTenantId();
  return useQuery({
    queryKey: key(tenantId, "total", resource, params),
    queryFn: ({ signal }) => directoryService[resource]({ ...params, pageSize: 1 }, { signal }),
    enabled,
    select: (page) => page.pagination?.totalItems ?? 0,
  });
}
