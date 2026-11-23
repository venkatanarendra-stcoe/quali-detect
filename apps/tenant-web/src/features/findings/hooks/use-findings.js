import { keepPreviousData, useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useSession, useTenantId } from "@/features/auth/hooks/use-session.js";
import { useCursorList } from "@/hooks/use-cursor-list.js";
import { usePageList } from "@/hooks/use-page-list.js";
import { toast } from "sonner";
import { describeError, isApiError } from "@/lib/api/index.js";
import { CONFLICT_TEXT, CREDENTIAL_SHAPE_TEXT, FORBIDDEN_TEXT } from "../constants/index.js";
import { conflictReason, validationDetails } from "../schemas/validate.js";
import { FINDINGS_MOCK_ENABLED, findingsService } from "../services/findings-service.js";
import { bindMockActor } from "../services/findings-api.mock.js";

/** Keys start with the tenant, then the workspace id, then `findings` (SCREENS 1): nothing crosses tenants or workspaces. */
export const findingKeys = {
  all: (tenantId, workspaceId) => ["tenant", tenantId, "workspace", workspaceId, "findings"],
  list: (t, w, params) => [...findingKeys.all(t, w), "list", params],
  summary: (t, w) => [...findingKeys.all(t, w), "summary"],
  detail: (t, w, id) => [...findingKeys.all(t, w), "detail", id],
  history: (t, w, id) => [...findingKeys.all(t, w), "history", id],
  comments: (t, w, id) => [...findingKeys.all(t, w), "comments", id],
  similar: (t, w, id) => [...findingKeys.all(t, w), "similar", id],
  queue: (t, w, params) => [...findingKeys.all(t, w), "queue", params],
  approvals: (t, w, params) => [...findingKeys.all(t, w), "approvals", params],
  board: (t, w, params) => [...findingKeys.all(t, w), "board", params],
  column: (t, w, column, params) => [...findingKeys.all(t, w), "column", column, params],
  pipelines: (t, w) => [...findingKeys.all(t, w), "pipelines"],
  assignees: (t, w, q) => [...findingKeys.all(t, w), "assignees", q],
};

/** No socket room for findings exists before Part B (SPEC 9.5): every screen polls every 60 s and refetches on focus. */
export const POLL_MS = 60_000;

/**
 * With `VITE_FINDINGS_MOCK=true` the mock needs the caller (id, name, permissions, workspace) to compute what the server
 * computes per caller (`allowedActions`, `canDecide`). Real mode: no-op.
 * @param {string} workspaceId
 */
export function useBindMockActor(workspaceId) {
  const { me } = useSession();
  if (FINDINGS_MOCK_ENABLED) {
    // bound during render on purpose: the first query of the page must already see the caller
    bindMockActor(() =>
      me?.user
        ? {
            userId: me.user.id,
            displayName: me.user.name,
            permissions: me.permissions,
            workspaceId,
          }
        : null,
    );
  }
}

/** Numbered finding list. @param {string} workspaceId @param {object} params filters and sort (no page) @param {object} paging */
export function useFindingList(workspaceId, params, paging, { enabled = true } = {}) {
  const tenantId = useTenantId();
  return usePageList({
    queryKey: findingKeys.list(tenantId, workspaceId, params),
    fetchPage: ({ page, pageSize }, signal) =>
      findingsService.list({ workspaceId, ...params, page, pageSize }, { signal }),
    enabled,
    refetchInterval: POLL_MS,
    ...paging,
  });
}

export function useFindingsSummary(workspaceId, { enabled = true } = {}) {
  const tenantId = useTenantId();
  return useQuery({
    queryKey: findingKeys.summary(tenantId, workspaceId),
    queryFn: ({ signal }) => findingsService.summary(workspaceId, { signal }),
    enabled,
    refetchInterval: POLL_MS,
  });
}

/** One finding (detail DTO with `lifecycle.allowedActions` and `rev`). */
export function useFinding(workspaceId, id, { enabled = true } = {}) {
  const tenantId = useTenantId();
  return useQuery({
    queryKey: findingKeys.detail(tenantId, workspaceId, id),
    queryFn: ({ signal }) => findingsService.get(id, { signal }),
    enabled: enabled && Boolean(id),
    staleTime: 0,
    retry: (count, error) => !(isApiError(error) && error.status < 500) && count < 2,
    refetchInterval: (query) =>
      query.state.data?.advisory?.status === "pending" ? 5_000 : POLL_MS,
  });
}

export function useFindingHistory(workspaceId, id, { enabled = true } = {}) {
  const tenantId = useTenantId();
  return useCursorList({
    queryKey: findingKeys.history(tenantId, workspaceId, id),
    fetchPage: (cursor, signal) => findingsService.history(id, { cursor, limit: 25 }, { signal }),
    enabled,
  });
}

export function useFindingComments(workspaceId, id, { enabled = true } = {}) {
  const tenantId = useTenantId();
  return useCursorList({
    queryKey: findingKeys.comments(tenantId, workspaceId, id),
    fetchPage: (cursor, signal) => findingsService.comments(id, { cursor, limit: 25 }, { signal }),
    enabled,
  });
}

export function useSimilarFindings(workspaceId, id, { enabled = true } = {}) {
  const tenantId = useTenantId();
  return useQuery({
    queryKey: findingKeys.similar(tenantId, workspaceId, id),
    queryFn: ({ signal }) => findingsService.similar(id, { signal }),
    enabled: enabled && Boolean(id),
  });
}

export function useReviewQueue(workspaceId, params, paging, { enabled = true } = {}) {
  const tenantId = useTenantId();
  return usePageList({
    queryKey: findingKeys.queue(tenantId, workspaceId, params),
    fetchPage: ({ page, pageSize }, signal) =>
      findingsService.reviewQueue({ workspaceId, ...params, page, pageSize }, { signal }),
    enabled,
    refetchInterval: POLL_MS,
    ...paging,
  });
}

export function useApprovalQueue(workspaceId, params, paging, { enabled = true } = {}) {
  const tenantId = useTenantId();
  return usePageList({
    queryKey: findingKeys.approvals(tenantId, workspaceId, params),
    fetchPage: ({ page, pageSize }, signal) =>
      findingsService.approvals({ workspaceId, ...params, page, pageSize }, { signal }),
    enabled,
    refetchInterval: POLL_MS,
    ...paging,
  });
}

export function useBoard(workspaceId, params, { enabled = true } = {}) {
  const tenantId = useTenantId();
  return useQuery({
    queryKey: findingKeys.board(tenantId, workspaceId, params),
    queryFn: ({ signal }) => findingsService.board({ workspaceId, ...params }, { signal }),
    enabled,
    refetchInterval: POLL_MS,
  });
}

export function usePipelineOptions(workspaceId) {
  const tenantId = useTenantId();
  return useQuery({
    queryKey: findingKeys.pipelines(tenantId, workspaceId),
    queryFn: ({ signal }) => findingsService.pipelines(workspaceId, { signal }),
    staleTime: 60_000,
  });
}

export function useAssigneeSearch(workspaceId, q, { enabled = true } = {}) {
  const tenantId = useTenantId();
  return useQuery({
    queryKey: findingKeys.assignees(tenantId, workspaceId, q),
    queryFn: ({ signal }) => findingsService.assignees(workspaceId, q, { signal }),
    enabled,
    placeholderData: keepPreviousData,
  });
}

/** Tenant settings keys: the tenant id first, nothing crosses tenants. */
export const slaSettingsKey = (tenantId) => ["tenant", tenantId, "settings", "findings-sla"];

/** The tenant's findings SLA targets (`GET /settings/findings-sla`, needs `tenant_settings.view`). @param {{ enabled?: boolean }} [options] */
export function useSlaSettings({ enabled = true } = {}) {
  const tenantId = useTenantId();
  return useQuery({
    queryKey: slaSettingsKey(tenantId),
    queryFn: ({ signal }) => findingsService.slaSettings({ signal }),
    enabled,
  });
}

/**
 * Saves the SLA targets (`PUT /settings/findings-sla`, needs `tenant_settings.manage`). The server answer replaces the cache (no
 * optimistic write). Not retroactive: the toast says so.
 */
export function useUpdateSlaSettings() {
  const tenantId = useTenantId();
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (targets) => findingsService.putSlaSettings({ targets }),
    onSuccess: (stored) => {
      queryClient.setQueryData(slaSettingsKey(tenantId), stored);
      toast.success("SLA targets saved.", {
        description: "Findings already open keep their due dates.",
      });
    },
    onError: (error) =>
      toast.error("Could not save the SLA targets.", { description: describeError(error) }),
  });
}

/**
 * Runs one finding write. `run(service)` returns the promise of the write (so the caller picks the function and arguments and
 * owns the Idempotency-Key); after it settles every findings query of the workspace is refetched (the detail the write returns
 * is put in the cache first, so the screen updates before the refetch).
 * @param {string} workspaceId
 */
export function useFindingAction(workspaceId) {
  const queryClient = useQueryClient();
  const tenantId = useTenantId();
  return useMutation({
    mutationFn: ({ run }) => run(findingsService),
    onSuccess: (data) => {
      if (data?.id && data?.lifecycle)
        queryClient.setQueryData(findingKeys.detail(tenantId, workspaceId, data.id), data);
    },
    onSettled: () =>
      queryClient.invalidateQueries({ queryKey: findingKeys.all(tenantId, workspaceId) }),
  });
}

/**
 * A sentence for a failed write, in plain words (never a permission key). Returns `{ text, field, conflict }`:
 * `conflict` is the `FINDING_STATE_CONFLICT` reason (the screen offers Reload), `field` the form field to focus.
 * @param {unknown} error
 */
export function describeActionError(error) {
  const conflict = conflictReason(error);
  if (conflict) return { text: CONFLICT_TEXT[conflict] ?? CONFLICT_TEXT.stale_revision, conflict };
  const validation = validationDetails(error);
  if (validation?.reason === "credential_shape")
    return { text: CREDENTIAL_SHAPE_TEXT, field: validation.field };
  if (validation?.reason === "expiry_out_of_range")
    return { text: "Choose an expiry within the allowed range.", field: "expiresAt" };
  if (validation?.reason === "assignee_not_eligible")
    return { text: "This person can't be assigned this finding.", field: "assigneeUserId" };
  if (validation?.reason === "approver_not_eligible")
    return {
      text: "This person can't approve this request. Choose another lead or leave it empty.",
      field: "requestedApproverUserId",
    };
  if (validation?.reason === "invalid_pull_request_url")
    return { text: "Enter an https link without credentials.", field: "pullRequestUrl" };
  if (
    isApiError(error) &&
    error.code === "CONFLICT" &&
    error.details?.reason === "workspace_archived"
  )
    return { text: "This workspace is archived, so findings can't change." };
  if (isApiError(error) && error.code === "IDEMPOTENCY_CONFLICT")
    return { text: "This action was already sent with different details. Reload and try again." };
  if (validation?.reason === "override_requires_tp")
    return {
      text: "A severity override only applies to a true positive.",
      field: "severityOverride",
    };
  if (isApiError(error) && error.status === 403) {
    return { text: FORBIDDEN_TEXT[error.details?.reason] ?? FORBIDDEN_TEXT.missing_permission };
  }
  if (isApiError(error) && error.status === 429)
    return { text: "Too many requests. Try again in a few minutes." };
  return { text: isApiError(error) ? error.message : "Something went wrong. Try again." };
}
