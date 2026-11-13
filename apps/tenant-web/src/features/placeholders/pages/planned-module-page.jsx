import { Hammer } from "lucide-react";
import { AppPageLayout } from "@qmentisai/ui";
import { EmptyState } from "@/components/states/empty-state.jsx";

/**
 * Honest placeholder for a module that is planned but not built. It is reachable only by users who hold the permission
 * (route guard) and shows no invented data.
 * @param {{ title: string, description?: string }} props
 */
export function PlannedModulePage({
  title,
  description = "This area is planned and not available yet.",
}) {
  return (
    <AppPageLayout title={title}>
      <EmptyState icon={Hammer} title="Coming soon" description={description} />
    </AppPageLayout>
  );
}
