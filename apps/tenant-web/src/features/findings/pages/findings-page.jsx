import { AppPageLayout } from "@qmentisai/ui";
import { useParams } from "react-router";
import { useFindingsRealtime } from "../hooks/use-findings-realtime.js";
import { FindingsList } from "../components/findings-list.jsx";

/**
 * T-31 Findings: find, filter and triage the workspace's findings. No mint button on this page (SCREENS 4). The route needs
 * `finding.view`; every action inside follows the central authorization engine and the DTO.
 */
export function FindingsPage() {
  const { workspaceId } = useParams();
  useFindingsRealtime(workspaceId);
  return (
    <AppPageLayout
      title="Findings"
      description="Issues found by scans of this workspace's pipelines."
      scroll={false}
    >
      <FindingsList workspaceId={workspaceId} />
    </AppPageLayout>
  );
}
