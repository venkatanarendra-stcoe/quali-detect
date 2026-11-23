import { Combobox } from "@qmentisai/ui";
import { Search, SlidersHorizontal, X } from "lucide-react";
import { useEffect, useMemo, useState } from "react";
import { Button } from "@/components/ui/button.jsx";
import { Input } from "@/components/ui/input.jsx";
import { Sheet, SheetContent, SheetDescription, SheetTitle } from "@/components/ui/sheet.jsx";
import { useMediaQuery } from "../hooks/use-media-query.js";
import { useDebouncedValue } from "@/hooks/use-debounced-value.js";
import {
  AI_SUGGESTION_OPTIONS,
  SCAN_TYPE_OPTIONS,
  SEVERITY_OPTIONS,
  SLA_OPTIONS,
  STATUS_OPTIONS,
} from "../constants/index.js";
import { SeverityBadge } from "./finding-bits.jsx";

/** A group of checkboxes (a labelled fieldset) writing a list back to the URL. */
function CheckGroup({ legend, options, value, onChange, render }) {
  return (
    <fieldset className="space-y-1.5">
      <legend className="mb-1 text-xs font-medium text-muted-foreground">{legend}</legend>
      {options.map((o) => (
        <label key={o.value} className="flex min-h-6 items-center gap-2 text-sm">
          <input
            type="checkbox"
            className="size-4 accent-[var(--foreground)]"
            checked={value.includes(o.value)}
            onChange={(e) =>
              onChange(e.target.checked ? [...value, o.value] : value.filter((v) => v !== o.value))
            }
          />
          {render ? render(o) : o.label}
        </label>
      ))}
    </fieldset>
  );
}

function PickerField({ id, label, children }) {
  return (
    <div>
      <span id={id} className="mb-1 block text-xs font-medium text-muted-foreground">
        {label}
      </span>
      {children}
    </div>
  );
}

/**
 * The search box of the list (rule, path, title; 2 to 100 characters). It writes the URL after a short pause; `/` focuses it from
 * anywhere on the page (wired by the list page through `inputRef`).
 */
export function FindingSearch({ value, onChange, inputRef }) {
  const [text, setText] = useState(value);
  const debounced = useDebouncedValue(text, 300);
  // an outside change (Clear all, a chip, Back) replaces the typed text; adjusting during render avoids an effect
  const [synced, setSynced] = useState(value);
  if (synced !== value) {
    setSynced(value);
    setText(value);
  }
  useEffect(() => {
    if (debounced !== value) onChange(debounced);
    // eslint-disable-next-line react-hooks/exhaustive-deps -- only a settled keystroke writes the URL
  }, [debounced]);
  return (
    <div className="relative w-full max-w-sm">
      <Search
        aria-hidden="true"
        className="pointer-events-none absolute top-2.5 left-2.5 size-4 text-muted-foreground"
      />
      <Input
        ref={inputRef}
        type="search"
        value={text}
        onChange={(e) => setText(e.target.value)}
        placeholder="Search rule, path or title"
        aria-label="Search findings by rule, path or title"
        aria-keyshortcuts="/"
        maxLength={100}
        className="pl-8"
      />
    </div>
  );
}

/**
 * The facet form of T-31 (SCREENS 4): severity, status, scan type, pipeline, repository, assignee, SLA, AI suggestion. Pure
 * controls over the URL state; `onChange` receives a partial update. On wide screens it is a left panel, below 1024 px a sheet.
 */
function FilterForm({ filters, onChange, pipelines, canAssignee = true }) {
  const repositories = useMemo(() => {
    const seen = new Map();
    for (const p of pipelines ?? []) if (p.repository) seen.set(p.repository.id, p.repository.name);
    return [...seen].map(([value, label]) => ({ value, label }));
  }, [pipelines]);
  return (
    <form aria-label="Filters" onSubmit={(e) => e.preventDefault()} className="space-y-4">
      <CheckGroup
        legend="Severity"
        options={SEVERITY_OPTIONS}
        value={filters.severity}
        onChange={(v) => onChange({ severity: v })}
        render={(o) => <SeverityBadge severity={o.value} />}
      />
      <CheckGroup
        legend="Status"
        options={STATUS_OPTIONS}
        value={filters.status}
        onChange={(v) => onChange({ status: v })}
      />
      <CheckGroup
        legend="Scan type"
        options={SCAN_TYPE_OPTIONS}
        value={filters.scanType}
        onChange={(v) => onChange({ scanType: v })}
      />
      <PickerField id="ff-pipeline" label="Pipeline">
        <Combobox
          aria-labelledby="ff-pipeline"
          options={(pipelines ?? []).map((p) => ({ value: p.id, label: p.name }))}
          value={filters.pipeline || null}
          onChange={(v) => onChange({ pipeline: v ?? "" })}
          placeholder="All pipelines"
          clearable
        />
      </PickerField>
      <PickerField id="ff-repo" label="Repository">
        <Combobox
          aria-labelledby="ff-repo"
          options={repositories}
          value={filters.repository || null}
          onChange={(v) => onChange({ repository: v ?? "" })}
          placeholder="All repositories"
          clearable
        />
      </PickerField>
      {canAssignee ? (
        <PickerField id="ff-assignee" label="Assignee">
          <Combobox
            aria-labelledby="ff-assignee"
            options={[
              { value: "me", label: "Me" },
              { value: "unassigned", label: "Unassigned" },
            ]}
            value={filters.assignee || null}
            onChange={(v) => onChange({ assignee: v ?? "" })}
            placeholder="Anyone"
            searchable={false}
            clearable
          />
        </PickerField>
      ) : null}
      <CheckGroup
        legend="SLA"
        options={SLA_OPTIONS}
        value={filters.sla}
        onChange={(v) => onChange({ sla: v })}
      />
      <PickerField id="ff-ai" label="AI suggestion">
        <Combobox
          aria-labelledby="ff-ai"
          options={AI_SUGGESTION_OPTIONS}
          value={filters.ai || null}
          onChange={(v) => onChange({ ai: v ?? "" })}
          placeholder="Any"
          searchable={false}
          clearable
        />
      </PickerField>
    </form>
  );
}

/** Removable chips for every active filter, with "Clear all". */
export function ActiveFilterChips({ filters, pipelines, onChange, onClear }) {
  const label = (list, value) => list.find((o) => o.value === value)?.label ?? value;
  const chips = [
    ...filters.severity.map((v) => ({
      key: `s-${v}`,
      text: `Severity: ${label(SEVERITY_OPTIONS, v)}`,
      clear: { severity: filters.severity.filter((x) => x !== v) },
    })),
    ...filters.status.map((v) => ({
      key: `st-${v}`,
      text: `Status: ${label(STATUS_OPTIONS, v)}`,
      clear: { status: filters.status.filter((x) => x !== v) },
    })),
    ...filters.scanType.map((v) => ({
      key: `t-${v}`,
      text: `Scan type: ${label(SCAN_TYPE_OPTIONS, v)}`,
      clear: { scanType: filters.scanType.filter((x) => x !== v) },
    })),
    filters.pipeline
      ? {
          key: "p",
          text: `Pipeline: ${pipelines?.find((p) => p.id === filters.pipeline)?.name ?? "…"}`,
          clear: { pipeline: "" },
        }
      : null,
    filters.repository
      ? {
          key: "r",
          text: `Repository: ${pipelines?.find((p) => p.repository?.id === filters.repository)?.repository.name ?? "…"}`,
          clear: { repository: "" },
        }
      : null,
    filters.assignee
      ? {
          key: "a",
          text: `Assignee: ${filters.assignee === "me" ? "Me" : filters.assignee === "unassigned" ? "Unassigned" : "Member"}`,
          clear: { assignee: "" },
        }
      : null,
    ...filters.sla.map((v) => ({
      key: `sla-${v}`,
      text: `SLA: ${v === "none" ? "No SLA" : label(SLA_OPTIONS, v)}`,
      clear: { sla: filters.sla.filter((x) => x !== v) },
    })),
    filters.ai
      ? {
          key: "ai",
          text: `AI suggestion: ${label(AI_SUGGESTION_OPTIONS, filters.ai)}`,
          clear: { ai: "" },
        }
      : null,
    filters.q ? { key: "q", text: `Search: ${filters.q}`, clear: { q: "" } } : null,
  ].filter(Boolean);
  if (!chips.length) return null;
  return (
    <ul className="mb-3 flex shrink-0 flex-wrap items-center gap-1.5" aria-label="Active filters">
      {chips.map((c) => (
        <li key={c.key}>
          <span className="inline-flex items-center gap-1 rounded-sm border border-border-strong py-0.5 pr-0.5 pl-2 text-xs">
            {c.text}
            <button
              type="button"
              aria-label={`Remove filter ${c.text}`}
              onClick={() => onChange(c.clear)}
              className="flex size-5 items-center justify-center rounded-sm outline-none hover:bg-accent focus-visible:ring-2 focus-visible:ring-ring"
            >
              <X aria-hidden="true" className="size-3" />
            </button>
          </span>
        </li>
      ))}
      <li>
        <Button size="sm" variant="ghost" onClick={onClear}>
          Clear all
        </Button>
      </li>
    </ul>
  );
}

/**
 * The filter panel: a left column at 1024 px and wider, a sheet below it (opened by the "Filters" button, which carries the
 * number of active facets). Focus returns to the button when the sheet closes (Radix).
 * @param {{ filters: any, onChange: (next: object) => void, pipelines?: any[], activeCount: number, canAssignee?: boolean }} props
 */
export function FilterPanel({
  filters,
  onChange,
  pipelines,
  activeCount,
  canAssignee,
  toolbar,
  children,
}) {
  const [open, setOpen] = useState(false);
  // on wide screens the panel is open from 1280 px and can be collapsed to give the table the width
  const roomy = useMediaQuery("(min-width: 1280px)");
  const [collapsed, setCollapsed] = useState(null);
  const showPanel = collapsed === null ? roomy : !collapsed;
  return (
    <div className="flex min-h-0 flex-1 flex-col">
      <div className="mb-3 flex shrink-0 flex-wrap items-center gap-3">
        {toolbar}
        <Button
          variant="secondary"
          className="lg:hidden"
          onClick={() => setOpen(true)}
          aria-haspopup="dialog"
        >
          <SlidersHorizontal aria-hidden="true" />
          Filters{activeCount ? ` (${activeCount})` : ""}
        </Button>
        <Button
          variant="secondary"
          className="max-lg:hidden"
          aria-expanded={showPanel}
          aria-controls="findings-filter-panel"
          onClick={() => setCollapsed(showPanel)}
        >
          <SlidersHorizontal aria-hidden="true" />
          {showPanel ? "Hide filters" : "Show filters"}
          {activeCount ? ` (${activeCount})` : ""}
        </Button>
      </div>
      <Sheet open={open} onOpenChange={setOpen}>
        <SheetContent className="lg:hidden">
          <SheetTitle className="text-base font-semibold">Filters</SheetTitle>
          <SheetDescription className="sr-only">Narrow the findings list.</SheetDescription>
          <FilterForm
            filters={filters}
            onChange={onChange}
            pipelines={pipelines}
            canAssignee={canAssignee}
          />
        </SheetContent>
      </Sheet>
      <div className="flex min-h-0 flex-1 gap-4">
        <aside
          id="findings-filter-panel"
          aria-label="Filter panel"
          className={`qm-scroll w-56 shrink-0 overflow-y-auto pr-2 ${showPanel ? "hidden lg:block" : "hidden"}`}
        >
          <FilterForm
            filters={filters}
            onChange={onChange}
            pipelines={pipelines}
            canAssignee={canAssignee}
          />
        </aside>
        <div className="flex min-h-0 min-w-0 flex-1 flex-col">{children}</div>
      </div>
    </div>
  );
}
