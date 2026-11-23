import { AppPageLayout } from "@qmentisai/ui";
import { useParams } from "react-router";
import { RemediationBoard } from "../components/remediation-board.jsx";

/**
 * T-36 Remediation: developers and dev leads see and move remediation work. The route needs `remediation.view`; moving cards needs
 * `finding.remediate` (own cards unless the user can also assign) and the server decides every move.
 */
export function RemediationPage() {
  const { workspaceId } = useParams();
  return (
    <AppPageLayout
      title="Remediation"
      description="Confirmed findings being fixed. Verified fixed and Reopened are set by scans."
      scroll={false}
    >
      <RemediationBoard workspaceId={workspaceId} />
    </AppPageLayout>
  );
}
