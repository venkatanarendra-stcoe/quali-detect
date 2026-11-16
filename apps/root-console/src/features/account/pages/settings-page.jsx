import { AppPageLayout } from "@qmentisai/ui";
import { Monitor, Moon, Sun } from "lucide-react";
import { useUiStore } from "@/app/stores/ui-store.js";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card.jsx";
import { TabsContent, TabsList, TabsTrigger, Tabs } from "@/components/ui/tabs.jsx";
import { cn } from "@/lib/cn.js";

const OPTIONS = [
  { value: "light", label: "Light", Icon: Sun },
  { value: "dark", label: "Dark", Icon: Moon },
  { value: "system", label: "System", Icon: Monitor },
];

function AppearanceTab() {
  const theme = useUiStore((s) => s.theme);
  const setTheme = useUiStore((s) => s.setTheme);
  return (
    <Card className="max-w-xl">
      <CardHeader>
        <CardTitle id="theme-heading">Theme</CardTitle>
        <CardDescription>
          Light, dark, or follow your system. The sidebar and the violet identity stay the same; the
          Root Console has no accent colour choice.
        </CardDescription>
      </CardHeader>
      <CardContent>
        <div role="group" aria-labelledby="theme-heading" className="flex flex-wrap gap-2">
          {OPTIONS.map(({ value, label, Icon }) => (
            <button
              key={value}
              type="button"
              aria-pressed={theme === value}
              onClick={() => setTheme(value)}
              className={cn(
                "flex h-9 items-center gap-2 rounded-sm border px-3 text-sm outline-none hover:bg-accent focus-visible:ring-2 focus-visible:ring-ring",
                theme === value
                  ? "border-foreground bg-accent font-medium"
                  : "border-border-strong",
              )}
            >
              <Icon aria-hidden="true" className="size-4" />
              {label}
            </button>
          ))}
        </div>
      </CardContent>
    </Card>
  );
}

/** Settings (own, no permission): Appearance (theme only) and Preferences. */
export function SettingsPage() {
  return (
    <AppPageLayout title="Settings" description="Settings that apply only to you." offset="4.5rem">
      <Tabs defaultValue="appearance">
        <TabsList>
          <TabsTrigger value="appearance">Appearance</TabsTrigger>
          <TabsTrigger value="preferences">Preferences</TabsTrigger>
        </TabsList>
        <TabsContent value="appearance" className="mt-4">
          <AppearanceTab />
        </TabsContent>
        <TabsContent value="preferences" className="mt-4">
          <Card className="max-w-xl">
            <CardHeader>
              <CardTitle>Preferences</CardTitle>
              <CardDescription>Personal options are planned.</CardDescription>
            </CardHeader>
          </Card>
        </TabsContent>
      </Tabs>
    </AppPageLayout>
  );
}
