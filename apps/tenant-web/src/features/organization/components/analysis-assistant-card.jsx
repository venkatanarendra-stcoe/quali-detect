import { Info, Sparkles } from "lucide-react";
import { useState } from "react";
import { ConfirmDialog } from "@/components/common/confirm-dialog.jsx";
import { QueryErrorState } from "@/components/states/error-state.jsx";
import { UnauthorizedState } from "@/components/states/unauthorized-state.jsx";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card.jsx";
import { Skeleton } from "@/components/ui/skeleton.jsx";
import { Switch } from "@/components/ui/switch.jsx";
import { useCan } from "@/features/authorization/hooks/use-permissions.js";
import { absoluteTime } from "@/features/executions/components/execution-bits.jsx";
import { useAiSettings, useUpdateAiConsent } from "../hooks/use-ai-settings.js";

const EXPLANATION =
  "When off, your scans are chosen by fixed rules only, unless this platform uses a local model. File names and change counts, never file contents, are sent. Changes are recorded in the audit log.";

function Frame({ children }) {
  return (
    <Card>
      <CardHeader>
        <CardTitle className="flex items-center gap-2">
          <Sparkles aria-hidden="true" className="size-4 text-muted-foreground" />
          Analysis assistant
        </CardTitle>
        <CardDescription>
          Helps choose which scans a change needs. It can only add scans to the required ones.
        </CardDescription>
      </CardHeader>
      <CardContent>{children}</CardContent>
    </Card>
  );
}

function Note({ children }) {
  return (
    <p className="flex items-start gap-2 text-sm">
      <Info aria-hidden="true" className="mt-0.5 size-4 shrink-0 text-muted-foreground" />
      {children}
    </p>
  );
}

function ConsentSwitch({ settings, canManage }) {
  const update = useUpdateAiConsent();
  const [confirmOpen, setConfirmOpen] = useState(false);
  const on = settings.externalConsent;
  const change = (next) => {
    if (next) setConfirmOpen(true);
    else update.mutate(false);
  };
  return (
    <div className="space-y-3">
      <div className="flex items-start gap-3">
        <Switch
          id="ai-consent"
          checked={on}
          disabled={!canManage || update.isPending}
          onCheckedChange={change}
          aria-describedby="ai-consent-help"
          aria-labelledby="ai-consent-label"
        />
        <div className="min-w-0 space-y-1 text-sm">
          <p id="ai-consent-label" className="font-medium">
            Allow external AI providers to receive file names of your repositories
          </p>
          <p id="ai-consent-help" className="text-muted-foreground">
            {EXPLANATION}
          </p>
        </div>
      </div>
      <p className="text-xs text-muted-foreground">
        {on ? "On" : "Off"}
        {settings.consentChangedAt ? (
          <>
            {" · last changed "}
            <time
              dateTime={settings.consentChangedAt}
              title={absoluteTime(settings.consentChangedAt)}
            >
              {absoluteTime(settings.consentChangedAt)}
            </time>
            {settings.consentChangedBy?.displayName
              ? ` by ${settings.consentChangedBy.displayName}`
              : ""}
          </>
        ) : (
          " · never changed"
        )}
      </p>
      {!canManage ? (
        <Note>You can see this setting but you cannot change it. Ask an administrator.</Note>
      ) : null}
      <ConfirmDialog
        open={confirmOpen}
        onOpenChange={(v) => {
          setConfirmOpen(v);
          if (!v) update.reset();
        }}
        title="Allow external AI providers?"
        description="File names and change counts of your repositories (never file contents) will be sent to the external provider this platform uses, to help choose scans. You can turn this off at any time. The change is recorded in the audit log."
        confirmLabel="Allow"
        pending={update.isPending}
        error={update.error}
        onConfirm={() => update.mutate(true, { onSuccess: () => setConfirmOpen(false) })}
      />
    </div>
  );
}

/**
 * "Analysis assistant" card of the organization Settings (docs/modules/scan-decisioning/SCREENS.md 3b). Seen with
 * `tenant_settings.view`, changed with `tenant_settings.manage`; the backend enforces both. The switch exists only when the
 * deployment uses an external provider (a local model needs no consent, no provider means nothing to switch).
 */
export function AnalysisAssistantCard() {
  const can = useCan();
  const canView = can("tenant_settings.view");
  const canManage = can("tenant_settings.manage");
  const query = useAiSettings({ enabled: canView });
  if (!canView)
    return (
      <Frame>
        <UnauthorizedState description="You don't have permission to see this setting." />
      </Frame>
    );
  if (query.isPending)
    return (
      <Frame>
        <div role="status" aria-busy="true" className="space-y-2">
          <span className="sr-only">Loading analysis assistant settings…</span>
          <Skeleton className="h-5 w-2/3" />
          <Skeleton className="h-10 w-full" />
        </div>
      </Frame>
    );
  if (query.isError)
    return (
      <Frame>
        <QueryErrorState error={query.error} onRetry={() => query.refetch()} />
      </Frame>
    );
  const settings = query.data;
  const kind = settings.assistant?.providerKind;
  return (
    <Frame>
      {!settings.assistant?.configured ? (
        <Note>
          The analysis assistant is not configured. Your scans are chosen by fixed rules only.
        </Note>
      ) : kind === "local" ? (
        <Note>
          This platform uses a local model, so no file names leave the platform and no consent is
          needed.
        </Note>
      ) : (
        <ConsentSwitch settings={settings} canManage={canManage} />
      )}
    </Frame>
  );
}
