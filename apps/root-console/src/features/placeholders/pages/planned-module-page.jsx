import { Hammer } from "lucide-react";
import { PageHeader } from "@/components/common/page-header.jsx";
import { EmptyState } from "@/components/states/empty-state.jsx";

/** Honest placeholder for a planned platform module: reachable only with the permission, shows no invented data. */
export function PlannedModulePage({
  title,
  description = "This area is planned and not available yet.",
}) {
  return (
    <>
      <PageHeader title={title} />
      <EmptyState icon={Hammer} title="Coming soon" description={description} />
    </>
  );
}
