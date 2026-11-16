import { AppPageLayout } from "@qmentisai/ui";
import { useParams } from "react-router";
import { ExecutionsList } from "../components/executions-list.jsx";

/**
 * T-28 Executions: every run of every pipeline in the workspace, newest first. Filters, sort and page size live in the URL;
 * rows page with numbered pagination (`page` and `limit` in the URL). There is no header button: a manual scan is a separate module.
 */
export function ExecutionsPage() {
  const { workspaceId } = useParams();
  return (
    <AppPageLayout
      title="Executions"
      description="Every run of every pipeline in this workspace."
      scroll={false}
    >
      <ExecutionsList workspaceId={workspaceId} caption="Executions" />
    </AppPageLayout>
  );
}
