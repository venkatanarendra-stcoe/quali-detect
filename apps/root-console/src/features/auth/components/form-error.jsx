import { describeError, isApiError } from "@/lib/api/index.js";

/** Inline error for the auth forms: generic message, rate-limit hint and the correlation id. */
export function FormError({ error }) {
  if (!error) return null;
  const retryAfter =
    isApiError(error) && error.code === "RATE_LIMITED" ? error.details?.retryAfterSeconds : null;
  return (
    <div
      role="alert"
      className="rounded-sm border border-border-strong bg-secondary px-3 py-2 text-sm"
    >
      <p className="text-status-danger">{describeError(error)}</p>
      {retryAfter ? (
        <p className="mt-1 text-xs text-muted-foreground">
          Try again in about {Math.max(1, Math.ceil(retryAfter / 60))} minute(s).
        </p>
      ) : null}
      {isApiError(error) && error.correlationId ? (
        <p className="mt-1 text-xs text-subtle-foreground">
          Reference <span className="font-mono">{error.correlationId}</span>
        </p>
      ) : null}
    </div>
  );
}
