import { toast } from "sonner";
import { QueryErrorState } from "@/components/states/error-state.jsx";
import { LoadingState } from "@/components/states/loading-state.jsx";
import { Card, CardContent } from "@/components/ui/card.jsx";
import { useCan } from "@/features/authorization/hooks/use-permissions.js";
import { describeError } from "@/lib/api/index.js";
import { useIntegrationSettings, useUpdateSettings } from "../hooks/use-integrations.js";

/** Tenant switch "Allow workspace admins to link source control". Editable with integration.manage, read-only otherwise. */
export function LinkingSetting() {
  const can = useCan();
  const canManage = can("integration.manage");
  const settings = useIntegrationSettings();
  const update = useUpdateSettings();
  if (settings.isPending) return <LoadingState label="Loading setting" rows={1} />;
  if (settings.isError)
    return <QueryErrorState error={settings.error} onRetry={settings.refetch} />;
  const on = settings.data.allowWorkspaceLinking;
  return (
    <Card>
      <CardContent className="space-y-1 pt-4">
        <div className="flex items-start gap-3 text-sm">
          <input
            id="linking-switch"
            type="checkbox"
            role="switch"
            className="mt-0.5"
            checked={on}
            disabled={!canManage || update.isPending}
            aria-describedby="linking-setting-help"
            onChange={() =>
              update.mutate(!on, {
                onSuccess: (data) =>
                  toast.success(
                    data.allowWorkspaceLinking
                      ? "Workspace admins can link source control"
                      : "Linking source control from workspaces is turned off",
                  ),
              })
            }
          />
          <div>
            <label htmlFor="linking-switch" className="font-medium">
              Allow workspace admins to link source control
            </label>
            <p id="linking-setting-help" className="text-xs text-muted-foreground">
              When off, workspaces cannot link new GitHub accounts. Existing links keep working.
              {canManage ? "" : " You need the integration.manage permission to change this."}
            </p>
          </div>
        </div>
        {update.error ? (
          <p role="alert" className="text-sm text-status-danger">
            {describeError(update.error)}
          </p>
        ) : null}
      </CardContent>
    </Card>
  );
}
