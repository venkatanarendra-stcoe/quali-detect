import { AppPageLayout } from "@qmentisai/ui";
import { FindingsSlaCard } from "@/features/findings/index.js";
import { AnalysisAssistantCard } from "../components/analysis-assistant-card.jsx";

/**
 * Organization settings (route guard: `tenant_settings.view`). Holds the Analysis assistant consent card (two switches: file names
 * and code excerpts) and the Findings SLA targets card.
 */
export function OrganizationSettingsPage() {
  return (
    <AppPageLayout
      title="Organization settings"
      description="Settings that apply to the whole organization."
    >
      <div className="max-w-3xl space-y-4">
        <AnalysisAssistantCard />
        <FindingsSlaCard />
      </div>
    </AppPageLayout>
  );
}
