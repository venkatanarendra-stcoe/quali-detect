import { DEFAULT_BRANCH_TOKEN, PIPELINE_SCAN_TYPES } from "@qmentisai/shared";
import { DataTable } from "@qmentisai/ui";
import { Badge } from "@/components/ui/badge.jsx";
import {
  FORK_POLICY_LABELS,
  PR_ACTION_LABELS,
  SCAN_LABELS,
  SEVERITY_LABELS,
  TRIGGER_LABELS,
} from "../constants/index.js";
import { describeCron, minutesOf } from "../schemas/index.js";

const EMPTY = "—";
const patternLabel = (p) => (p === DEFAULT_BRANCH_TOKEN ? "default branch" : p);

/** Wrapped chips for multi-value fields; `mono` for branch/glob patterns (identifiers). Empty -> the one empty glyph. */
function Chips({ values, mono = false }) {
  if (!values?.length) return EMPTY;
  return (
    <ul className="flex flex-wrap gap-1.5">
      {values.map((v, i) => (
        <li
          key={`${v}-${i}`}
          className={
            mono
              ? "max-w-full rounded-sm border border-border bg-secondary px-1.5 py-0.5 font-mono text-xs [overflow-wrap:anywhere]"
              : "rounded-sm border border-border bg-secondary px-1.5 py-0.5 text-xs"
          }
        >
          {v}
        </li>
      ))}
    </ul>
  );
}

/**
 * Definition list as a two-column grid: label (min 140px) and value (shrinkable, wraps by word). In a container narrower
 * than 22rem (two trigger cards side by side at 1280 px) the label sits above the value instead, so a value never
 * shrinks to a few characters.
 */
function Dl({ children }) {
  return (
    <div className="@container min-w-0">
      <dl className="grid grid-cols-1 gap-x-4 gap-y-0.5 text-sm @[22rem]:grid-cols-[minmax(140px,10rem)_minmax(0,1fr)] @[22rem]:gap-y-2">
        {children}
      </dl>
    </div>
  );
}

/** `mono` is for a single long identifier/code value (may break anywhere); normal text breaks by word only. */
function Row({ label, children, mono = false }) {
  return (
    <>
      <dt className="mt-1.5 text-muted-foreground first:mt-0 @[22rem]:mt-0">{label}</dt>
      <dd
        className={
          mono
            ? "min-w-0 font-mono text-xs [overflow-wrap:anywhere]"
            : "min-w-0 [overflow-wrap:break-word]"
        }
      >
        {children}
      </dd>
    </>
  );
}

/** The options of one trigger as a definition list. */
export function TriggerDetails({ trigger }) {
  return (
    <Dl>
      {trigger.type === "push" ? (
        <>
          <Row label="Branches">
            <Chips mono values={(trigger.branches?.include ?? []).map(patternLabel)} />
          </Row>
          <Row label="Excluded branches">
            <Chips mono values={(trigger.branches?.exclude ?? []).map(patternLabel)} />
          </Row>
          <Row label="Tags">
            {trigger.tags?.enabled ? (
              <Chips mono values={trigger.tags.include ?? []} />
            ) : (
              "Not scanned"
            )}
          </Row>
          <Row label="New branches">
            {trigger.onBranchCreated === "run" ? "Scanned" : "Skipped"}
          </Row>
          <Row label="Force pushes">{trigger.onForcePush === "run" ? "Scanned" : "Skipped"}</Row>
        </>
      ) : null}
      {trigger.type === "pull_request" ? (
        <>
          <Row label="Actions">
            <Chips values={(trigger.actions ?? []).map((a) => PR_ACTION_LABELS[a] ?? a)} />
          </Row>
          <Row label="Target branches">
            <Chips mono values={(trigger.targetBranches?.include ?? []).map(patternLabel)} />
          </Row>
          <Row label="Draft pull requests">{trigger.drafts === "run" ? "Run" : "Skip"}</Row>
          <Row label="Fork pull requests">
            {FORK_POLICY_LABELS[trigger.forkPolicy] ?? trigger.forkPolicy}
          </Row>
        </>
      ) : null}
      {trigger.type === "schedule" ? (
        <>
          <Row label="Cron" mono>
            {trigger.cron || EMPTY}
          </Row>
          <Row label="Reads as">{describeCron(trigger.cron) ?? EMPTY}</Row>
          <Row label="Time zone" mono>
            {trigger.timezone || EMPTY}
          </Row>
          <Row label="Ref" mono>
            {trigger.ref === DEFAULT_BRANCH_TOKEN ? "default branch" : trigger.ref || EMPTY}
          </Row>
          <Row label="Scan kind">{trigger.scanKind === "full" ? "Full" : "Incremental"}</Row>
          <Row label="Missed runs">{trigger.missedPolicy === "run_once" ? "Run once" : "Skip"}</Row>
        </>
      ) : null}
      {trigger.type === "manual" ? (
        <Row label="Run now">Allowed for people who can run pipelines</Row>
      ) : null}
    </Dl>
  );
}

function TriggerBlock({ trigger }) {
  return (
    <section
      aria-label={`${TRIGGER_LABELS[trigger.type]} trigger`}
      title={`Trigger key: ${trigger.key}`}
      className="min-w-0 rounded-md border border-border p-3"
    >
      <h4 className="mb-3 flex items-center justify-between gap-2 text-sm font-medium">
        <span className="min-w-0 truncate">
          {TRIGGER_LABELS[trigger.type]}
          {trigger.type === "schedule" ? (
            <span className="ml-2 font-mono text-xs font-normal text-muted-foreground">
              {trigger.key}
            </span>
          ) : null}
        </span>
        <Badge tone={trigger.enabled ? "success" : "neutral"} className="shrink-0">
          {trigger.enabled ? "On" : "Off"}
        </Badge>
      </h4>
      <TriggerDetails trigger={trigger} />
    </section>
  );
}

/** Read-only view of one configuration version (it contains no secret by construction). */
export function ConfigView({ config }) {
  const scans = PIPELINE_SCAN_TYPES.map((type) => [type, config.scans?.[type]]);
  return (
    <div className="space-y-5">
      <section>
        <h3 className="mb-2 text-sm font-semibold">Triggers</h3>
        <div className="grid gap-3 xl:grid-cols-2">
          {(config.triggers ?? []).length === 0 ? (
            <p className="text-sm text-muted-foreground">No triggers.</p>
          ) : null}
          {(config.triggers ?? []).map((t) => (
            <TriggerBlock key={t.key} trigger={t} />
          ))}
        </div>
      </section>
      <section>
        <h3 className="mb-2 text-sm font-semibold">Scans</h3>
        <Dl>
          {scans.map(([type, scan]) => (
            <Row key={type} label={SCAN_LABELS[type]}>
              {scan?.enabled
                ? `On · engine ${scan.engine?.id ?? "default"}${scan.engine?.profile ? ` (${scan.engine.profile})` : ""} · threshold ${SEVERITY_LABELS[scan.severityThreshold] ?? scan.severityThreshold}`
                : "Off"}
            </Row>
          ))}
          <Row label="Excluded paths">
            <Chips mono values={config.exclusions?.paths ?? []} />
          </Row>
        </Dl>
      </section>
      <section>
        <h3 className="mb-2 text-sm font-semibold">Execution controls</h3>
        <Dl>
          <Row label="Scan mode">
            {config.scanMode?.default === "full" ? "Full" : "Incremental"}
          </Row>
          <Row label="Timeout">{minutesOf(config.execution?.timeoutSeconds ?? 0)} min</Row>
          <Row label="Scan task timeout">
            {minutesOf(config.execution?.scanTaskTimeoutSeconds ?? 0)} min
          </Row>
          <Row label="Concurrency">
            {config.execution?.concurrency?.policy}
            {config.execution?.concurrency?.policy === "queue"
              ? ` (up to ${config.execution.concurrency.maxQueued} queued)`
              : ""}
          </Row>
          <Row label="Cancellation">
            {config.execution?.cancellation === "immediate" ? "Immediate" : "Graceful"}
          </Row>
          <Row label="Fail the pipeline on">
            {SEVERITY_LABELS[config.failOn?.severity] ?? config.failOn?.severity} ·{" "}
            {config.failOn?.scope === "all" ? "all findings" : "new findings only"} · engine errors{" "}
            {config.failOn?.onEngineError === "ignore" ? "ignored" : "fail the run"}
          </Row>
        </Dl>
      </section>
    </div>
  );
}

const flat = (value, prefix, out) => {
  if (value && typeof value === "object" && !Array.isArray(value)) {
    const keys = Object.keys(value);
    if (keys.length === 0 && prefix) out.set(prefix, "{}");
    for (const k of keys) flat(value[k], prefix ? `${prefix}.${k}` : k, out);
  } else out.set(prefix, Array.isArray(value) ? JSON.stringify(value) : String(value));
};
function flatten(config) {
  const out = new Map();
  const { triggers = [], ...rest } = config ?? {};
  flat(rest, "", out);
  for (const t of triggers) flat(t, `triggers.${t.key}`, out);
  return out;
}

/**
 * Differences between two configurations as rows `{ path, kind, before, after }` (SPEC §7.2 shows paths in lists; the viewer
 * of a version already sees its values, so the page shows both sides). Triggers are matched by key.
 */
export function diffConfigs(previous, next) {
  const a = flatten(previous);
  const b = flatten(next);
  const rows = [];
  for (const [path, after] of b) {
    if (!a.has(path)) rows.push({ path, kind: "added", before: null, after });
    else if (a.get(path) !== after)
      rows.push({ path, kind: "changed", before: a.get(path), after });
  }
  for (const [path, before] of a)
    if (!b.has(path)) rows.push({ path, kind: "removed", before, after: null });
  return rows.sort((x, y) => x.path.localeCompare(y.path));
}

const KIND = { added: "Added", changed: "Changed", removed: "Removed" };

const DIFF_COLUMNS = [
  {
    id: "setting",
    header: "Setting",
    cell: ({ row: { original: r } }) => (
      <span className="font-mono text-xs break-all">{r.path}</span>
    ),
  },
  { id: "change", header: "Change", cell: ({ row: { original: r } }) => KIND[r.kind] },
  {
    id: "before",
    header: "Before",
    cell: ({ row: { original: r } }) => (
      <span className="font-mono text-xs break-all">{r.before ?? "—"}</span>
    ),
  },
  {
    id: "after",
    header: "After",
    cell: ({ row: { original: r } }) => (
      <span className="font-mono text-xs break-all">{r.after ?? "—"}</span>
    ),
  },
];

/** Diff table of two configurations; `previous` null means the first version. */
export function ConfigDiff({ previous, next, title }) {
  const rows = diffConfigs(previous, next);
  return (
    <section aria-label={title}>
      <h3 className="mb-2 text-sm font-semibold">{title}</h3>
      {rows.length === 0 ? (
        <p className="text-sm text-muted-foreground">No differences.</p>
      ) : (
        <DataTable
          caption={title}
          columns={DIFF_COLUMNS}
          data={rows}
          getRowId={(r) => r.path}
          height="auto"
          maxHeight="22rem"
        />
      )}
    </section>
  );
}
