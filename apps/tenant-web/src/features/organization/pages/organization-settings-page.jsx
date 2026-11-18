import { AppPageLayout } from "@qmentisai/ui";
import { AnalysisAssistantCard } from "../components/analysis-assistant-card.jsx";

/** Organization settings (route guard: `tenant_settings.view`). Today it holds the Analysis assistant consent card. */
export function OrganizationSettingsPage() {
  return (
    <AppPageLayout
      title="Organization settings"
      description="Settings that apply to the whole organization."
    >
      <div className="max-w-3xl space-y-4">
        <AnalysisAssistantCard />
      </div>
    </AppPageLayout>
  );
}
