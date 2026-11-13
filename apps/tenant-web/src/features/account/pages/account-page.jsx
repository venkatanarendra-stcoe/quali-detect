import { DEFAULT_ACCENT } from "@qmentisai/shared";
import { AppPageLayout } from "@qmentisai/ui";
import { useState } from "react";
import { QueryErrorState } from "@/components/states/error-state.jsx";
import { Button } from "@/components/ui/button.jsx";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card.jsx";
import { Skeleton } from "@/components/ui/skeleton.jsx";
import { ScrollTabs, ScrollTabsContent } from "@/components/ui/scroll-tabs.jsx";
import { TabsList, TabsTrigger } from "@/components/ui/tabs.jsx";
import { AccentPicker } from "../components/accent-picker.jsx";
import { AccentPreview } from "../components/accent-preview.jsx";
import { ACCENT_LABELS } from "../constants/accents.js";
import { usePreferences, useUpdatePreferences } from "../hooks/use-preferences.js";

function PreferencesForm({ saved }) {
  const [draft, setDraft] = useState(null); // null = nothing chosen yet (shows the saved accent)
  const update = useUpdatePreferences({ successMessage: "Accent colour saved." });
  const chosen = draft ?? saved;
  const dirty = chosen !== saved;

  return (
    <div className="grid gap-6 lg:grid-cols-[minmax(0,1fr)_minmax(0,1fr)]">
      <Card>
        <CardHeader>
          <CardTitle id="accent-heading">Accent colour</CardTitle>
          <CardDescription>
            Fills your primary buttons, the active navigation item and the keyboard focus ring.
            Severity and status colours never change.
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <AccentPicker
            aria-labelledby="accent-heading"
            value={chosen}
            onChange={setDraft}
            disabled={update.isPending}
          />
          <div className="flex flex-wrap items-center gap-2">
            <Button
              disabled={!dirty || update.isPending}
              onClick={() => update.mutate({ accent: chosen }, { onSuccess: () => setDraft(null) })}
            >
              Save
            </Button>
            <Button
              variant="secondary"
              disabled={update.isPending || (saved === DEFAULT_ACCENT && chosen === DEFAULT_ACCENT)}
              onClick={() =>
                update.mutate({ accent: DEFAULT_ACCENT }, { onSuccess: () => setDraft(null) })
              }
            >
              Reset to default ({ACCENT_LABELS[DEFAULT_ACCENT]})
            </Button>
          </div>
        </CardContent>
      </Card>
      <Card>
        <CardHeader>
          <CardTitle>Preview</CardTitle>
          <CardDescription>
            {ACCENT_LABELS[chosen]}
            {dirty ? " (not saved yet)" : ""}
          </CardDescription>
        </CardHeader>
        <CardContent>
          <AccentPreview accent={chosen} />
        </CardContent>
      </Card>
    </div>
  );
}

function PreferencesTab() {
  const preferences = usePreferences();
  if (preferences.isPending)
    return (
      <div role="status" aria-busy="true" className="space-y-3">
        <span className="sr-only">Loading preferences…</span>
        <Skeleton className="h-40 w-full" />
      </div>
    );
  if (preferences.isError)
    return <QueryErrorState error={preferences.error} onRetry={() => preferences.refetch()} />;
  return <PreferencesForm saved={preferences.data.accent} />;
}

/** Account (T-03). Any signed-in user may open it: preferences are the user's own and need no permission. */
export function AccountPage() {
  return (
    <AppPageLayout title="Account" description="Settings that apply only to you." scroll={false}>
      <ScrollTabs defaultValue="preferences">
        <TabsList className="shrink-0">
          <TabsTrigger value="preferences">Preferences</TabsTrigger>
        </TabsList>
        <ScrollTabsContent value="preferences">
          <PreferencesTab />
        </ScrollTabsContent>
      </ScrollTabs>
    </AppPageLayout>
  );
}
