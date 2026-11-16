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
import { Label } from "@/components/ui/label.jsx";
import { Select } from "@/components/ui/select.jsx";
import { Skeleton } from "@/components/ui/skeleton.jsx";
import { ScrollTabs, ScrollTabsContent } from "@/components/ui/scroll-tabs.jsx";
import { TabsList, TabsTrigger } from "@/components/ui/tabs.jsx";
import { ThemePicker } from "../components/theme-picker.jsx";
import { AccentPicker } from "../components/accent-picker.jsx";
import { AccentPreview } from "../components/accent-preview.jsx";
import { ACCENT_LABELS } from "../constants/accents.js";
import { usePermissions } from "@/features/authorization/hooks/use-permissions.js";
import { usePreferences, useUpdatePreferences } from "../hooks/use-preferences.js";

function AppearanceForm({ saved }) {
  const [draft, setDraft] = useState(null); // null = nothing chosen yet (shows the saved accent)
  const update = useUpdatePreferences({ successMessage: "Accent colour saved." });
  const chosen = draft ?? saved;
  const dirty = chosen !== saved;

  return (
    <div className="grid gap-6 lg:grid-cols-[minmax(0,1fr)_minmax(0,1fr)]">
      <Card className="lg:col-span-2">
        <CardHeader>
          <CardTitle id="theme-heading">Theme</CardTitle>
          <CardDescription>
            Light, dark, or follow your system. Stored on this device.
          </CardDescription>
        </CardHeader>
        <CardContent>
          <ThemePicker aria-labelledby="theme-heading" />
        </CardContent>
      </Card>
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

function AppearanceTab() {
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
  return <AppearanceForm saved={preferences.data.accent} />;
}

/**
 * Default workspace: where you land after signing in. The choices are ONLY the workspaces you can access right now (the
 * workspaces of your permission set from `GET /me`); the server validates the choice again on save and at every sign-in, and
 * the preference never grants access. Nothing chosen = the standard landing.
 */
function DefaultWorkspaceCard({ saved }) {
  const { workspaces } = usePermissions();
  const [draft, setDraft] = useState(null); // null = nothing changed yet (shows the saved value)
  const update = useUpdatePreferences({ successMessage: "Default workspace saved." });
  const chosen = draft ?? saved ?? "";
  const dirty = chosen !== (saved ?? "");
  const save = () =>
    update.mutate(
      { defaultWorkspaceId: chosen === "" ? null : chosen },
      { onSuccess: () => setDraft(null) },
    );

  return (
    <Card className="max-w-xl">
      <CardHeader>
        <CardTitle id="default-workspace-heading">Default workspace</CardTitle>
        <CardDescription>
          The workspace dashboard you land on after signing in. If you lose access to it, or leave
          this empty, you land on the organization overview (administrators) or on your first
          workspace.
        </CardDescription>
      </CardHeader>
      <CardContent className="space-y-4">
        <div className="space-y-1.5">
          <Label htmlFor="default-workspace">Workspace</Label>
          <Select
            id="default-workspace"
            value={chosen}
            onChange={(event) => setDraft(event.target.value)}
            disabled={update.isPending}
          >
            <option value="">No default (standard landing)</option>
            {workspaces.map((workspace) => (
              <option key={workspace.id} value={workspace.id}>
                {workspace.name}
              </option>
            ))}
          </Select>
          {workspaces.length === 0 ? (
            <p className="text-xs text-muted-foreground">
              You do not have access to any workspace yet.
            </p>
          ) : null}
        </div>
        <Button disabled={!dirty || update.isPending} onClick={save}>
          Save
        </Button>
      </CardContent>
    </Card>
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
  return (
    <div className="space-y-6">
      <DefaultWorkspaceCard saved={preferences.data.defaultWorkspaceId} />
      <Card className="max-w-xl">
        <CardHeader>
          <CardTitle>More preferences</CardTitle>
          <CardDescription>
            Notification delivery and time zone are planned. Appearance (theme and accent colour) is
            on the Appearance tab.
          </CardDescription>
        </CardHeader>
      </Card>
    </div>
  );
}

/** Settings (own, any signed-in user, no permission): Appearance (theme + accent) and Preferences. */
export function SettingsPage() {
  return (
    <AppPageLayout title="Settings" description="Settings that apply only to you." scroll={false}>
      <ScrollTabs defaultValue="appearance">
        <TabsList className="shrink-0">
          <TabsTrigger value="appearance">Appearance</TabsTrigger>
          <TabsTrigger value="preferences">Preferences</TabsTrigger>
        </TabsList>
        <ScrollTabsContent value="appearance">
          <AppearanceTab />
        </ScrollTabsContent>
        <ScrollTabsContent value="preferences">
          <PreferencesTab />
        </ScrollTabsContent>
      </ScrollTabs>
    </AppPageLayout>
  );
}
