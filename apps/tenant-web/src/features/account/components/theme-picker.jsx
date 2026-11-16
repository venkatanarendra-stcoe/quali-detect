import { Monitor, Moon, Sun } from "lucide-react";
import { useUiStore } from "@/app/stores/ui-store.js";
import { cn } from "@/lib/cn.js";

const OPTIONS = [
  { value: "light", label: "Light", Icon: Sun },
  { value: "dark", label: "Dark", Icon: Moon },
  { value: "system", label: "System", Icon: Monitor },
];

/**
 * Light / Dark / System choice (Settings > Appearance). Toggle buttons with `aria-pressed`: each is a tab stop, the
 * selected one also shows a border and a label, so colour is never the only cue.
 * @param {{ "aria-labelledby"?: string }} props
 */
export function ThemePicker({ "aria-labelledby": labelledBy }) {
  const theme = useUiStore((s) => s.theme);
  const setTheme = useUiStore((s) => s.setTheme);
  return (
    <div role="group" aria-labelledby={labelledBy} className="flex flex-wrap gap-2">
      {OPTIONS.map(({ value, label, Icon }) => (
        <button
          key={value}
          type="button"
          aria-pressed={theme === value}
          onClick={() => setTheme(value)}
          className={cn(
            "flex h-9 items-center gap-2 rounded-sm border px-3 text-sm outline-none hover:bg-accent focus-visible:ring-2 focus-visible:ring-ring",
            theme === value ? "border-foreground bg-accent font-medium" : "border-border-strong",
          )}
        >
          <Icon aria-hidden="true" className="size-4" />
          {label}
        </button>
      ))}
    </div>
  );
}
