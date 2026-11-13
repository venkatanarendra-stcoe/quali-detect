import { CircleCheck, CircleX } from "lucide-react";
import { Badge } from "@/components/ui/badge.jsx";
import { Sheet, SheetContent, SheetDescription, SheetTitle } from "@/components/ui/sheet.jsx";

const when = (value) =>
  new Date(value).toLocaleString(undefined, { dateStyle: "medium", timeStyle: "medium" });

function Field({ label, children }) {
  return (
    <div>
      <dt className="text-xs text-muted-foreground">{label}</dt>
      <dd className="mt-0.5 text-sm break-words">{children}</dd>
    </div>
  );
}

/**
 * Detail side sheet for one audit entry (the normal app theme): time, actor, action, target, result, correlation id and
 * the changes, metadata and IP address that the table does not show. Closing returns focus to the originating row.
 * @param {{ entry: object | null, onClose: () => void, returnFocusTo?: { current: HTMLElement | null } }} props
 */
export function AuditEntrySheet({ entry, onClose, returnFocusTo }) {
  return (
    <Sheet open={entry !== null} onOpenChange={(open) => (open ? undefined : onClose())}>
      <SheetContent
        aria-describedby={undefined}
        onCloseAutoFocus={(event) => {
          // no trigger element opened this sheet, so put focus back on the originating row ourselves
          event.preventDefault();
          returnFocusTo?.current?.focus();
        }}
      >
        {entry ? (
          <>
            <div className="pr-6">
              <SheetTitle className="font-mono text-base font-semibold break-all">
                {entry.action}
              </SheetTitle>
              <SheetDescription className="mt-1 text-sm text-muted-foreground">
                {when(entry.createdAt)}
              </SheetDescription>
            </div>
            <dl className="grid gap-3">
              <Field label="Result">
                {entry.result === "failure" ? (
                  <Badge tone="danger">
                    <CircleX aria-hidden="true" />
                    Failure
                  </Badge>
                ) : (
                  <Badge tone="success">
                    <CircleCheck aria-hidden="true" />
                    Success
                  </Badge>
                )}
              </Field>
              <Field label="Actor">
                {entry.actor?.name ?? entry.actor?.type ?? "System"}
                {entry.actor?.email ? (
                  <span className="block text-xs text-muted-foreground">{entry.actor.email}</span>
                ) : null}
              </Field>
              <Field label="Resource">
                {entry.target?.type ?? "—"}
                {entry.target?.id ? (
                  <span className="block font-mono text-xs text-muted-foreground">
                    {entry.target.id}
                  </span>
                ) : null}
              </Field>
              <Field label="Correlation ID">
                <span className="font-mono text-xs">{entry.correlationId ?? "—"}</span>
              </Field>
              <Field label="IP address">
                <span className="font-mono text-xs">{entry.ipAddress ?? "—"}</span>
              </Field>
              <Field label="Changes and metadata">
                <pre className="max-h-96 overflow-auto rounded-sm bg-secondary p-2 font-mono text-xs">
                  {JSON.stringify({ changes: entry.changes, metadata: entry.metadata }, null, 2)}
                </pre>
              </Field>
            </dl>
          </>
        ) : null}
      </SheetContent>
    </Sheet>
  );
}
