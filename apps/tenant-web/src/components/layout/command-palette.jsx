import { Search } from "lucide-react";
import { useEffect, useId, useMemo, useRef, useState } from "react";
import { useNavigate } from "react-router";
import { Dialog, DialogContent, DialogDescription, DialogTitle } from "@/components/ui/dialog.jsx";
import { cn } from "@/lib/cn.js";

/**
 * Whether the global Ctrl/Cmd+K listener is registered. OFF since 2026-11-16: the palette trigger was removed from the
 * sidebar by owner decision and the component is intentionally unused (kept in place, not deleted); nothing mounts it.
 * Re-enable only together with a mounted trigger.
 */
const GLOBAL_SHORTCUT_ENABLED = false;

/**
 * Global jump palette (⌘K / Ctrl+K), the owner-approved home of the former top-bar search. It only lists pages the
 * caller already sees in the sidebar (`entries` are built from `evaluateNavigation`'s output) plus the user's own
 * Account and Settings pages, so it can never reveal a page the navigation hides. Combobox pattern: the input keeps
 * focus, arrows move the active option, Enter opens it, Escape closes and focus returns to the trigger.
 * @param {{ entries: { id: string, label: string, group: string, to: string }[], open: boolean,
 *   onOpenChange: (open: boolean) => void, onNavigate?: () => void,
 *   returnFocusRef?: import("react").RefObject<HTMLElement | null> }} props
 */
export function CommandPalette({ entries, open, onOpenChange, onNavigate, returnFocusRef }) {
  const navigate = useNavigate();
  const listId = useId();
  const [query, setQuery] = useState("");
  const [active, setActive] = useState(0);
  const listRef = useRef(null);

  useEffect(() => {
    if (!GLOBAL_SHORTCUT_ENABLED) return undefined;
    const onKey = (event) => {
      if ((event.metaKey || event.ctrlKey) && event.key.toLowerCase() === "k") {
        event.preventDefault();
        onOpenChange(true);
      }
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [onOpenChange]);

  const results = useMemo(() => {
    const q = query.trim().toLowerCase();
    return q ? entries.filter((e) => `${e.label} ${e.group}`.toLowerCase().includes(q)) : entries;
  }, [entries, query]);

  const choose = (entry) => {
    onOpenChange(false);
    navigate(entry.to);
    onNavigate?.();
  };
  const onKeyDown = (event) => {
    if (results.length === 0) return;
    if (event.key === "ArrowDown" || event.key === "ArrowUp") {
      event.preventDefault();
      const step = event.key === "ArrowDown" ? 1 : -1;
      const next = (active + step + results.length) % results.length;
      setActive(next);
      listRef.current?.children[next]?.scrollIntoView({ block: "nearest" });
    } else if (event.key === "Enter") {
      event.preventDefault();
      choose(results[Math.min(active, results.length - 1)]);
    }
  };
  const activeIndex = Math.min(active, Math.max(results.length - 1, 0));

  return (
    <Dialog
      open={open}
      onOpenChange={(next) => {
        onOpenChange(next);
        if (!next) {
          setQuery("");
          setActive(0);
        }
      }}
    >
      <DialogContent
        onCloseAutoFocus={(event) => {
          // No Radix Trigger here (the palette also opens from ⌘K): put focus back on the search control ourselves.
          event.preventDefault();
          returnFocusRef?.current?.focus();
        }}
        className="top-[20%] max-w-md -translate-y-0 p-0"
      >
        <DialogTitle className="sr-only">Search or jump to</DialogTitle>
        <DialogDescription className="sr-only">
          Type to filter pages, use the arrow keys to choose one and press Enter to open it.
        </DialogDescription>
        <div className="flex items-center gap-2 border-b border-border px-3">
          <Search aria-hidden="true" className="size-4 shrink-0 text-muted-foreground" />
          <input
            role="combobox"
            aria-expanded="true"
            aria-controls={listId}
            aria-activedescendant={results.length ? `${listId}-${activeIndex}` : undefined}
            aria-label="Search or jump to"
            autoComplete="off"
            value={query}
            onChange={(event) => {
              setQuery(event.target.value);
              setActive(0);
            }}
            onKeyDown={onKeyDown}
            placeholder="Search or jump to…"
            className="h-11 w-full bg-transparent pr-8 text-sm outline-none placeholder:text-muted-foreground"
          />
        </div>
        <ul
          ref={listRef}
          id={listId}
          role="listbox"
          aria-label="Pages"
          className="max-h-72 overflow-y-auto p-1"
        >
          {results.map((entry, index) => (
            // Combobox pattern: the input keeps focus and handles the keyboard; options are pointer targets only.
            // eslint-disable-next-line jsx-a11y/click-events-have-key-events
            <li
              key={entry.id}
              id={`${listId}-${index}`}
              role="option"
              aria-selected={index === activeIndex}
              onMouseMove={() => setActive(index)}
              onClick={() => choose(entry)}
              className={cn(
                "flex cursor-default items-center justify-between gap-3 rounded-sm px-2 py-1.5 text-sm",
                index === activeIndex && "bg-accent text-accent-foreground",
              )}
            >
              <span className="truncate">{entry.label}</span>
              <span className="shrink-0 text-xs text-muted-foreground">{entry.group}</span>
            </li>
          ))}
        </ul>
        {results.length === 0 ? (
          <p role="status" className="px-3 py-6 text-center text-sm text-muted-foreground">
            No pages match “{query}”.
          </p>
        ) : null}
      </DialogContent>
    </Dialog>
  );
}
