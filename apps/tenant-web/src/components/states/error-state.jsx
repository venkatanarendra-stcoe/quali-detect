import { TriangleAlert } from "lucide-react";
import { Button } from "@/components/ui/button.jsx";
import { describeError, isApiError } from "@/lib/api/index.js";
import { NotFoundState } from "./not-found-state.jsx";
import { StateLayout } from "./state-layout.jsx";
import { UnauthorizedState } from "./unauthorized-state.jsx";

/**
 * Error with the correlation id so the user can quote it to support (T-05). 5xx and transport failures offer Retry.
 * @param {{ error?: unknown, onRetry?: () => void, fullPage?: boolean, title?: string }} props
 */
export function ErrorState({ error, onRetry, fullPage = false, title = "Something went wrong" }) {
  const correlationId = isApiError(error) ? error.correlationId : null;
  return (
    <StateLayout
      icon={TriangleAlert}
      title={title}
      fullPage={fullPage}
      role="alert"
      actions={
        onRetry ? (
          <Button variant="secondary" onClick={() => onRetry()}>
            Try again
          </Button>
        ) : null
      }
    >
      <p>{describeError(error)}</p>
      {correlationId ? (
        <p className="text-xs text-subtle-foreground">
          Reference <span className="font-mono">{correlationId}</span>
        </p>
      ) : null}
    </StateLayout>
  );
}

/**
 * Maps a failed query to the right deliberate state: 403 -> unauthorized, 404 -> not found, everything else -> error.
 * @param {{ error: unknown, onRetry?: () => void }} props
 */
export function QueryErrorState({ error, onRetry }) {
  if (isApiError(error) && error.status === 403 && error.code !== "TENANT_SUSPENDED")
    return <UnauthorizedState />;
  if (isApiError(error) && error.status === 404) return <NotFoundState />;
  return <ErrorState error={error} onRetry={onRetry} />;
}
