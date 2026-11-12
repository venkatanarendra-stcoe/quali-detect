import { matchIncludeExclude } from "@qmentisai/shared";
import { useState } from "react";
import { Input } from "@/components/ui/input.jsx";
import { Label } from "@/components/ui/label.jsx";
import { Switch } from "@/components/ui/switch.jsx";
import { Textarea } from "@/components/ui/textarea.jsx";
import { cn } from "@/lib/cn.js";
import { linesToList } from "../schemas/index.js";

/** Messages for a path and everything below it. @param {Record<string, string[]>} errors @param {string} prefix */
export function errorsFor(errors, prefix) {
  return Object.entries(errors)
    .filter(([path]) => path === prefix || path.startsWith(`${prefix}.`))
    .flatMap(([, messages]) => messages);
}

/** Label, control, hint and error messages wired with aria-describedby. */
export function Field({ id, label, hint, errors = [], children, className }) {
  return (
    <div className={cn("space-y-1.5", className)}>
      <Label htmlFor={id}>{label}</Label>
      {children}
      {hint ? (
        <p id={`${id}-hint`} className="text-xs text-subtle-foreground">
          {hint}
        </p>
      ) : null}
      {errors.map((m, i) => (
        <p key={i} id={`${id}-err-${i}`} role="alert" className="text-xs text-status-danger">
          {m}
        </p>
      ))}
    </div>
  );
}

/** One pattern per line (mono). Keeps the raw text while typing; the list is what the form holds. */
export function PatternListField({ id, label, hint, value, onChange, errors = [], placeholder }) {
  const [text, setText] = useState(value.join("\n"));
  const [seen, setSeen] = useState(value);
  if (seen !== value) {
    // external change (reset, reload): resync only when the list differs from what the text already means
    setSeen(value);
    if (JSON.stringify(linesToList(text)) !== JSON.stringify(value)) setText(value.join("\n"));
  }
  return (
    <Field id={id} label={label} hint={hint} errors={errors}>
      <Textarea
        id={id}
        className="min-h-16 font-mono text-xs"
        value={text}
        placeholder={placeholder}
        aria-invalid={errors.length > 0}
        aria-describedby={hint ? `${id}-hint` : undefined}
        spellCheck={false}
        onChange={(e) => {
          setText(e.target.value);
          onChange(linesToList(e.target.value));
        }}
      />
    </Field>
  );
}

/** Which sample names match the include/exclude lists (exclude wins; an empty include matches nothing). */
export function PatternTester({ id, include, exclude, defaultBranch, kind = "branch" }) {
  const [sample, setSample] = useState("");
  const names = linesToList(sample.replace(/,/g, "\n"));
  return (
    <div className="space-y-1.5 rounded-md border border-dashed border-border p-3">
      <Label htmlFor={id}>Try {kind} names (comma separated)</Label>
      <Input
        id={id}
        className="font-mono text-xs"
        value={sample}
        onChange={(e) => setSample(e.target.value)}
        placeholder={kind === "tag" ? "v1.2.0, rc-1" : "main, release/1.0, feature/login"}
        autoComplete="off"
        spellCheck={false}
      />
      {names.length > 0 ? (
        <ul aria-live="polite" className="space-y-0.5 text-xs">
          {names.map((n) => {
            const r = matchIncludeExclude(n, { include, exclude }, { defaultBranch });
            return (
              <li key={n}>
                <span className="font-mono">{n}</span>{" "}
                <span className={r.matched ? "text-status-success" : "text-muted-foreground"}>
                  {r.matched ? "matches" : r.reason === "excluded" ? "excluded" : "does not match"}
                </span>
              </li>
            );
          })}
        </ul>
      ) : null}
    </div>
  );
}

/** Card with a title, an on/off switch and its body. The body stays visible when off (dimmed) so nothing is lost. */
export function TriggerCard({
  id,
  icon: Icon,
  title,
  subtitle,
  enabled,
  onToggle,
  children,
  actions,
}) {
  return (
    <section aria-labelledby={`${id}-title`} className="rounded-md border border-border bg-card">
      <header className="flex items-start justify-between gap-3 border-b border-border p-4">
        <div className="min-w-0">
          <h3 id={`${id}-title`} className="flex items-center gap-2 text-sm font-semibold">
            {Icon ? <Icon aria-hidden="true" className="size-4 text-muted-foreground" /> : null}
            {title}
          </h3>
          {subtitle ? <p className="mt-0.5 text-xs text-muted-foreground">{subtitle}</p> : null}
        </div>
        <div className="flex items-center gap-2">
          {actions}
          <Switch aria-labelledby={`${id}-title`} checked={enabled} onCheckedChange={onToggle} />
        </div>
      </header>
      <div className={cn("space-y-3 p-4", !enabled && "opacity-60")}>{children}</div>
    </section>
  );
}
