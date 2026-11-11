import { X } from "lucide-react";
import { Input } from "@/components/ui/input.jsx";
import { Label } from "@/components/ui/label.jsx";
import { cn } from "@/lib/cn.js";
import { describeError } from "@/lib/api/index.js";

/**
 * Search-and-choose control for people or groups. The parent owns the query and the options (server-side search), so no
 * large lists are loaded. Selecting shows a removable chip. Options: `{ id, label, hint? }`.
 * @param {{ id: string, label: string, placeholder?: string, query: string, onQueryChange: (q: string) => void, options: any[], isLoading?: boolean, error?: unknown, selected: any | null, onSelect: (option: any) => void, onClear: () => void, emptyText?: string, disabled?: boolean }} props
 */
export function SearchPicker({
  id,
  label,
  placeholder,
  query,
  onQueryChange,
  options,
  isLoading,
  error,
  selected,
  onSelect,
  onClear,
  emptyText = "No matches.",
  disabled,
}) {
  return (
    <div className="space-y-1.5">
      <Label htmlFor={id}>{label}</Label>
      {selected ? (
        <div className="flex h-9 items-center justify-between rounded-sm border border-input bg-secondary px-3 text-sm">
          <span className="truncate">
            {selected.label}
            {selected.hint ? (
              <span className="text-muted-foreground"> · {selected.hint}</span>
            ) : null}
          </span>
          <button
            type="button"
            onClick={onClear}
            aria-label={`Clear ${label.toLowerCase()}`}
            className="ml-2 flex size-6 items-center justify-center rounded-sm text-muted-foreground outline-none hover:bg-accent focus-visible:ring-2 focus-visible:ring-ring"
          >
            <X aria-hidden="true" className="size-3.5" />
          </button>
        </div>
      ) : (
        <>
          <Input
            id={id}
            type="search"
            placeholder={placeholder}
            value={query}
            onChange={(e) => onQueryChange(e.target.value)}
            disabled={disabled}
            autoComplete="off"
          />
          <ul
            role="listbox"
            aria-label={`${label} results`}
            className={cn(
              "max-h-40 overflow-y-auto rounded-sm border border-border bg-card",
              options.length === 0 && "p-2 text-sm text-muted-foreground",
            )}
          >
            {error ? (
              <li role="alert" className="p-2 text-sm text-status-danger">
                {describeError(error)}
              </li>
            ) : null}
            {isLoading && options.length === 0 ? (
              <li className="p-2 text-sm text-muted-foreground">Searching…</li>
            ) : null}
            {!error && !isLoading && options.length === 0 ? <li>{emptyText}</li> : null}
            {options.map((option) => (
              <li key={option.id} role="option" aria-selected="false">
                <button
                  type="button"
                  onClick={() => onSelect(option)}
                  className="flex w-full items-center justify-between gap-2 px-3 py-1.5 text-left text-sm outline-none hover:bg-secondary focus-visible:bg-secondary"
                >
                  <span className="truncate">{option.label}</span>
                  {option.hint ? (
                    <span className="truncate text-xs text-muted-foreground">{option.hint}</span>
                  ) : null}
                </button>
              </li>
            ))}
          </ul>
        </>
      )}
    </div>
  );
}
