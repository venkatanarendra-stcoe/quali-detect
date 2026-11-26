import { useActiveWorkspace } from "@/features/authorization/hooks/use-permissions.js";
import { WorkspaceDashboardView } from "@/features/reporting/index.js";

/**
 * Workspace dashboard (T-20 charts, T-21 tables with `?view=table`): always the active workspace. The content is the Reporting
 * module's; this page only supplies the workspace the URL names (`WorkspaceScope` has already answered 404 for one the person
 * cannot see).
 */
export function WorkspaceDashboardPage() {
  const active = useActiveWorkspace();
  return <WorkspaceDashboardView workspaceId={active.id} workspaceName={active.name} />;
}
