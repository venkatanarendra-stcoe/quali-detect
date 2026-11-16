import { Combobox, MultiSelect } from "@qmentisai/ui";
import { SlidersHorizontal, X } from "lucide-react";
import { useCallback, useState } from "react";
import { Button } from "@/components/ui/button.jsx";
import { Input } from "@/components/ui/input.jsx";
import { pipelinesService } from "@/features/pipelines/services/pipelines-service.js";
import { usePipeline } from "@/features/pipelines/hooks/use-pipelines.js";
import {
  ACTIVE_STATUSES,
  FILTER_STATUSES,
  TRIGGER_FILTERS,
  executionStatus,
} from "../constants/index.js";

const DAY_MS = 86_400_000;
const MAX_RANGE_DAYS = 400;
const startOfDay = (day) => new Date(`${day}T00:00:00`);

/** `from` / `to` day inputs -> UTC instants on the requested time; `to` is exclusive, so it is the start of the NEXT day. */
export function rangeToInstants(from, to) {
  const start = from ? startOfDay(from) : null;
  const end = to ? new Date(startOfDay(to).getTime() + DAY_MS) : null;
  return {
    from: start && !Number.isNaN(start.getTime()) ? start.toISOString() : undefined,
    to: end && !Number.isNaN(end.getTime()) ? end.toISOString() : undefined,
  };
}

/** Inline message for a reversed or too long range, else null. */
export function rangeProblem(from, to) {
  if (!from || !to) return null;
  const { from: a, to: b } = rangeToInstants(from, to);
  if (!a || !b) return null;
  const span = new Date(b).getTime() - new Date(a).getTime();
  if (span <= 0) return "The end date is before the start date.";
  if (span > MAX_RANGE_DAYS * DAY_MS) return `Choose a range of at most ${MAX_RANGE_DAYS} days.`;
  return null;
}

const STATUS_OPTIONS = FILTER_STATUSES.map((value) => ({
  value,
  label: executionStatus(value).label,
}));
const sameSet = (a, b) => a.length === b.length && a.every((v) => b.includes(v));

/**
 * Filter bar of T-28 (and the pipeline tab, `showPipeline={false}`): status, pipeline, repository, trigger and the date range.
 * Pure controls over the URL state `filters` (`{ status: string[], pipeline, repository, trigger, from, to }`); `onChange`
 * receives a partial update. Removable chips repeat every active filter; the date range sits behind "More filters" below 1440.
 */
export function ExecutionFilters({
  workspaceId,
  filters,
  onChange,
  onClear,
  repositories,
  showPipeline = true,
  trailing,
}) {
  const [moreOpen, setMoreOpen] = useState(false);
  const loadPipelines = useCallback(
    async (query, { signal }) => {
      const page = await pipelinesService.list(
        { workspaceId, q: query || undefined, limit: 20 },
        { signal },
      );
      return page.items.map((p) => ({ value: p.id, label: p.name }));
    },
    [workspaceId],
  );
  const selectedPipeline = usePipeline(filters.pipeline, { enabled: Boolean(filters.pipeline) });
  const problem = rangeProblem(filters.from, filters.to);
  const dates = moreOpen || filters.from || filters.to;
  const activePreset = sameSet(filters.status, ACTIVE_STATUSES);
  const repoOptions = (repositories ?? []).map((r) => ({ value: r.id, label: r.fullName }));
  const chips = [
    filters.status.length
      ? {
          key: "status",
          label: `Status: ${filters.status.map((s) => executionStatus(s).label).join(", ")}`,
          clear: { status: [] },
        }
      : null,
    showPipeline && filters.pipeline
      ? {
          key: "pipeline",
          label: `Pipeline: ${selectedPipeline.data?.name ?? "…"}`,
          clear: { pipeline: "" },
        }
      : null,
    filters.repository
      ? {
          key: "repository",
          label: `Repository: ${repoOptions.find((r) => r.value === filters.repository)?.label ?? "…"}`,
          clear: { repository: "" },
        }
      : null,
    filters.trigger
      ? {
          key: "trigger",
          label: `Trigger: ${TRIGGER_FILTERS.find((t) => t.value === filters.trigger)?.label ?? filters.trigger}`,
          clear: { trigger: "" },
        }
      : null,
    filters.from ? { key: "from", label: `From ${filters.from}`, clear: { from: "" } } : null,
    filters.to ? { key: "to", label: `To ${filters.to}`, clear: { to: "" } } : null,
  ].filter(Boolean);

  return (
    <div className="mb-4 shrink-0 space-y-2">
      <div className="flex flex-wrap items-end gap-3">
        <div className="w-60">
          <span id="ex-status-l" className="mb-1 block text-xs text-muted-foreground">
            Status
          </span>
          <MultiSelect
            aria-labelledby="ex-status-l"
            options={STATUS_OPTIONS}
            value={filters.status}
            onChange={(value) => onChange({ status: value })}
            placeholder="All statuses"
          />
        </div>
        <Button
          variant="secondary"
          aria-pressed={activePreset}
          onClick={() => onChange({ status: activePreset ? [] : [...ACTIVE_STATUSES] })}
        >
          Active
        </Button>
        {showPipeline ? (
          <div className="w-52">
            <span id="ex-pipeline-l" className="mb-1 block text-xs text-muted-foreground">
              Pipeline
            </span>
            <Combobox
              aria-labelledby="ex-pipeline-l"
              loadOptions={loadPipelines}
              options={
                filters.pipeline
                  ? [{ value: filters.pipeline, label: selectedPipeline.data?.name ?? "…" }]
                  : []
              }
              value={filters.pipeline || null}
              onChange={(value) => onChange({ pipeline: value ?? "" })}
              placeholder="All pipelines"
              searchPlaceholder="Search pipelines"
              clearable
            />
          </div>
        ) : null}
        {repositories ? (
          <div className="w-52">
            <span id="ex-repo-l" className="mb-1 block text-xs text-muted-foreground">
              Repository
            </span>
            <Combobox
              aria-labelledby="ex-repo-l"
              options={repoOptions}
              value={filters.repository || null}
              onChange={(value) => onChange({ repository: value ?? "" })}
              placeholder="All repositories"
              clearable
            />
          </div>
        ) : null}
        <div className="w-40">
          <span id="ex-trigger-l" className="mb-1 block text-xs text-muted-foreground">
            Trigger
          </span>
          <Combobox
            aria-labelledby="ex-trigger-l"
            options={TRIGGER_FILTERS}
            value={filters.trigger || null}
            onChange={(value) => onChange({ trigger: value ?? "" })}
            placeholder="All triggers"
            searchable={false}
            clearable
          />
        </div>
        <Button
          variant="ghost"
          className="min-[1440px]:hidden"
          aria-expanded={Boolean(dates)}
          onClick={() => setMoreOpen((open) => !open)}
        >
          <SlidersHorizontal aria-hidden="true" />
          More filters
        </Button>
        <div
          className={dates ? "flex items-end gap-3" : "hidden items-end gap-3 min-[1440px]:flex"}
        >
          <div>
            <label htmlFor="ex-from" className="mb-1 block text-xs text-muted-foreground">
              From
            </label>
            <Input
              id="ex-from"
              type="date"
              value={filters.from}
              max={filters.to || undefined}
              aria-invalid={Boolean(problem)}
              aria-describedby={problem ? "ex-range-problem" : undefined}
              onChange={(e) => onChange({ from: e.target.value })}
            />
          </div>
          <div>
            <label htmlFor="ex-to" className="mb-1 block text-xs text-muted-foreground">
              To
            </label>
            <Input
              id="ex-to"
              type="date"
              value={filters.to}
              min={filters.from || undefined}
              aria-invalid={Boolean(problem)}
              aria-describedby={problem ? "ex-range-problem" : undefined}
              onChange={(e) => onChange({ to: e.target.value })}
            />
          </div>
        </div>
        {chips.length ? (
          <Button variant="ghost" onClick={onClear}>
            Clear all
          </Button>
        ) : null}
        {trailing ? <div className="ml-auto flex items-center gap-2 pb-1.5">{trailing}</div> : null}
      </div>
      {problem ? (
        <p id="ex-range-problem" role="alert" className="text-xs text-status-danger">
          {problem}
        </p>
      ) : null}
      {chips.length ? (
        <ul className="flex flex-wrap gap-1.5" aria-label="Active filters">
          {chips.map((chip) => (
            <li key={chip.key}>
              <span className="inline-flex items-center gap-1 rounded-sm border border-border-strong py-0.5 pr-0.5 pl-2 text-xs">
                {chip.label}
                <button
                  type="button"
                  aria-label={`Remove filter ${chip.label}`}
                  onClick={() => onChange(chip.clear)}
                  className="flex size-4 items-center justify-center rounded-sm text-muted-foreground outline-none hover:bg-accent focus-visible:ring-2 focus-visible:ring-ring"
                >
                  <X aria-hidden="true" className="size-3" />
                </button>
              </span>
            </li>
          ))}
        </ul>
      ) : null}
    </div>
  );
}
