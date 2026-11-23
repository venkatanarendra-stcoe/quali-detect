import { AppPageLayout } from "@qmentisai/ui";
import { useParams } from "react-router";
import { useFindingsRealtime } from "../hooks/use-findings-realtime.js";
import { ApprovalsQueue } from "../components/approvals-queue.jsx";

/**
 * T-35 Approvals: leads approve or reject pending decisions (true or false positive, accepted risk, suppression). The route needs
 * `approval.view`; approving needs `approval.approve`, rejecting `approval.reject` (the sheet is read only without them).
 */
export function ApprovalsPage() {
  const { workspaceId } = useParams();
  useFindingsRealtime(workspaceId);
  return (
    <AppPageLayout
      title="Approvals"
      description="Decisions and requests that need a lead. You can't approve your own."
      scroll={false}
    >
      <ApprovalsQueue workspaceId={workspaceId} />
    </AppPageLayout>
  );
}
