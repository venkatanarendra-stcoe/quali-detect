import { Info, TriangleAlert } from "lucide-react";
import { Button } from "@/components/ui/button.jsx";
import { Label } from "@/components/ui/label.jsx";

/**
 * A labelled form field: label, optional hint, the control (`children`), a live character counter and the inline error linked
 * with `aria-describedby` (the control must use `describedBy(id, ...)`).
 * @param {{ id: string, label: any, hint?: any, error?: string, counter?: { value: number, max: number }, required?: boolean, children: any }} props
 */
export function Field({ id, label, hint, error, counter, required, children }) {
  return (
    <div className="space-y-1.5">
      <Label htmlFor={id}>
        {label}
        {required ? <span className="text-muted-foreground"> (required)</span> : null}
      </Label>
      {children}
      <div className="flex items-start justify-between gap-3 text-xs">
        <div className="min-w-0 space-y-0.5">
          {hint ? (
            <p id={`${id}-hint`} className="text-subtle-foreground">
              {hint}
            </p>
          ) : null}
          {error ? (
            <p id={`${id}-error`} role="alert" className="text-status-danger">
              {error}
            </p>
          ) : null}
        </div>
        {counter ? (
          <span
            className={`shrink-0 tabular-nums ${counter.value > counter.max ? "text-status-danger" : "text-subtle-foreground"}`}
          >
            {counter.value.toLocaleString()} / {counter.max.toLocaleString()}
          </span>
        ) : null}
      </div>
    </div>
  );
}

/** `aria-describedby` and `aria-invalid` for a control of `Field`. @param {string} id @param {boolean} hasHint @param {string | undefined} error */
export const describedBy = (id, hasHint, error) => ({
  "aria-describedby":
    [hasHint ? `${id}-hint` : null, error ? `${id}-error` : null].filter(Boolean).join(" ") ||
    undefined,
  "aria-invalid": error ? true : undefined,
});

/**
 * The "This finding changed" banner of a 409 (SCREENS 6): the typed text stays in the form; Reload refetches the finding.
 * @param {{ text: string, onReload?: () => void }} props
 */
export function ConflictBanner({ text, onReload }) {
  return (
    <div
      role="alert"
      className="flex flex-wrap items-center justify-between gap-2 rounded-md border border-border-strong bg-secondary px-3 py-2 text-sm"
    >
      <span className="flex items-center gap-1.5">
        <TriangleAlert aria-hidden="true" className="size-4 shrink-0 text-status-warning" />
        {text}
      </span>
      {onReload ? (
        <Button size="sm" variant="secondary" onClick={onReload}>
          Reload
        </Button>
      ) : null}
    </div>
  );
}

/** A quiet notice with an info icon (segregation of duties notes, limits). @param {{ children: any, id?: string }} props */
export function InfoNote({ children, id }) {
  return (
    <p id={id} className="flex items-start gap-1.5 text-sm text-muted-foreground">
      <Info aria-hidden="true" className="mt-0.5 size-4 shrink-0" />
      <span>{children}</span>
    </p>
  );
}
