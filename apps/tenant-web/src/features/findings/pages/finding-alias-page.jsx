import { useQuery } from "@tanstack/react-query";
import { Navigate, useLocation, useParams } from "react-router";
import { QueryErrorState } from "@/components/states/error-state.jsx";
import { LoadingState } from "@/components/states/loading-state.jsx";
import { NotFoundState } from "@/components/states/not-found-state.jsx";
import { useTenantId } from "@/features/auth/hooks/use-session.js";
import { findingsService } from "../services/findings-service.js";

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

/**
 * The wireframe route `/findings/:findingId` (SCREENS 2, T-32) has no workspace in the URL. The workspace comes from
 * `GET /findings/{id}` (the detail DTO carries `workspaceId`; the API authorizes the read in the finding's own workspace). A
 * finding of another tenant, in a hidden workspace or that does not exist is the same 404 (`NotFoundState`); a workspace the caller
 * can see but without `finding.view` is 403 (`UnauthorizedState`). Nothing is cached under the workspace until the redirect.
 */
export function FindingAliasRedirect() {
  const { findingId } = useParams();
  const { search } = useLocation();
  const tenantId = useTenantId();
  const valid = UUID.test(findingId ?? "");
  const finding = useQuery({
    queryKey: ["tenant", tenantId, "finding-alias", findingId],
    queryFn: ({ signal }) => findingsService.get(findingId, { signal }),
    enabled: valid,
    retry: false,
    staleTime: 0,
  });
  if (!valid) return <NotFoundState />;
  if (finding.isPending) return <LoadingState label="Opening finding" rows={2} />;
  if (finding.isError) return <QueryErrorState error={finding.error} onRetry={finding.refetch} />;
  if (!finding.data?.workspaceId) return <NotFoundState />;
  return (
    <Navigate
      to={`/workspaces/${finding.data.workspaceId}/findings/${finding.data.id}${search}`}
      replace
    />
  );
}
