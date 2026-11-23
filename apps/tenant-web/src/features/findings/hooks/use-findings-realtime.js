import { useQueryClient } from "@tanstack/react-query";
import { useCallback, useEffect, useRef } from "react";
import { useTenantId } from "@/features/auth/hooks/use-session.js";
import { useRealtime } from "@/features/executions/hooks/use-realtime.js";
import { FINDINGS_MOCK_ENABLED } from "../services/findings-service.js";
import { findingKeys } from "./use-findings.js";

/** Several hints in one burst (a bulk call, an outbox batch) become one refetch round. */
const COALESCE_MS = 400;

/**
 * Joins the findings room of a workspace (`{ findingsWorkspaceId }`, SPEC findings 9.5) while the page is mounted and invalidates
 * the workspace's findings queries when a `finding.changed` hint arrives. The hint is ids and enums only: it is NEVER shown or
 * written to the cache as data; the screen refetches through the API (which re-authorizes). The 60 s polling stays as the fallback
 * (no change to the intervals): `live` only tells the page whether the socket is up.  Invalidation only marks
 * queries stale; the forms hold their own state, so a refetch never overwrites what the user is typing.
 * With the mock on, there is no socket.
 * @param {string | undefined} workspaceId
 * @param {{ enabled?: boolean }} [options]
 * @returns {{ live: boolean }}
 */
export function useFindingsRealtime(workspaceId, { enabled = true } = {}) {
  const queryClient = useQueryClient();
  const tenantId = useTenantId();
  const timer = useRef(null);
  useEffect(() => () => clearTimeout(timer.current), []);
  const onHint = useCallback(
    (name) => {
      if (name !== "finding.changed" || !workspaceId) return;
      clearTimeout(timer.current);
      timer.current = setTimeout(() => {
        queryClient.invalidateQueries({ queryKey: findingKeys.all(tenantId, workspaceId) });
      }, COALESCE_MS);
    },
    [queryClient, tenantId, workspaceId],
  );
  const { live } = useRealtime({
    scope: "findings",
    id: workspaceId,
    enabled: enabled && Boolean(workspaceId) && !FINDINGS_MOCK_ENABLED,
    onHint,
  });
  return { live };
}
