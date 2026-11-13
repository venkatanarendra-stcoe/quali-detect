import { Hammer } from "lucide-react";
import { AppPageLayout } from "@qmentisai/ui";
import { EmptyState } from "@/components/states/empty-state.jsx";

/** Honest placeholder for a planned platform module: reachable only with the permission, shows no invented data. */
export function PlannedModulePage({
  title,
  description = "This area is planned and not available yet.",
}) {
  return (
    <AppPageLayout title={title} offset="7.5rem">
      <EmptyState icon={Hammer} title="Coming soon" description={description} />
    </AppPageLayout>
  );
}
