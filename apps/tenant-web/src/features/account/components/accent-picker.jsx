import { Check } from "lucide-react";
import { useRef } from "react";
import { cn } from "@/lib/cn.js";
import { ACCENT_OPTIONS } from "../constants/accents.js";

/**
 * Swatch radio group. Roving tabindex: one tab stop, arrow keys move the selection (wrapping), Home/End jump. Each swatch
 * shows its colour AND a label; the selected one also shows a check mark (colour is never the only cue).
 * @param {{ value: string, onChange: (key: string) => void, disabled?: boolean, "aria-labelledby"?: string }} props
 */
export function AccentPicker({ value, onChange, disabled = false, "aria-labelledby": labelledBy }) {
  const refs = useRef([]);

  const move = (index) => {
    const next = (index + ACCENT_OPTIONS.length) % ACCENT_OPTIONS.length;
    onChange(ACCENT_OPTIONS[next].key);
    refs.current[next]?.focus();
  };
  const onKeyDown = (event, index) => {
    const keys = {
      ArrowRight: index + 1,
      ArrowDown: index + 1,
      ArrowLeft: index - 1,
      ArrowUp: index - 1,
      Home: 0,
      End: ACCENT_OPTIONS.length - 1,
    };
    if (!(event.key in keys)) return;
    event.preventDefault();
    move(keys[event.key]);
  };

  return (
    <div
      role="radiogroup"
      aria-labelledby={labelledBy}
      className="grid grid-cols-3 gap-2 sm:grid-cols-5"
    >
      {ACCENT_OPTIONS.map((option, index) => {
        const selected = option.key === value;
        return (
          <button
            key={option.key}
            ref={(el) => {
              refs.current[index] = el;
            }}
            type="button"
            role="radio"
            aria-checked={selected}
            aria-label={option.label}
            disabled={disabled}
            tabIndex={selected ? 0 : -1}
            onClick={() => onChange(option.key)}
            onKeyDown={(event) => onKeyDown(event, index)}
            className={cn(
              "flex flex-col items-center gap-1.5 rounded-md border px-2 py-3 text-sm outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2 focus-visible:ring-offset-background disabled:opacity-50",
              selected
                ? "border-foreground bg-secondary font-medium"
                : "border-border-strong hover:bg-accent",
            )}
          >
            <span
              data-accent-preview={option.key}
              aria-hidden="true"
              className="flex size-8 items-center justify-center rounded-full bg-primary text-primary-foreground"
            >
              {selected ? <Check className="size-4" strokeWidth={2.5} /> : null}
            </span>
            <span>{option.label}</span>
          </button>
        );
      })}
    </div>
  );
}
