import { DEFAULT_BRANCH_TOKEN, PIPELINE_SCAN_TYPES } from "@qmentisai/shared";
import { Badge } from "@/components/ui/badge.jsx";
import {
  FORK_POLICY_LABELS,
  PR_ACTION_LABELS,
  SCAN_LABELS,
  SEVERITY_LABELS,
  TRIGGER_LABELS,
} from "../constants/index.js";
import { describeCron, minutesOf } from "../schemas/index.js";

const list = (patterns) =>
  patterns?.length
    ? patterns.map((p) => (p === DEFAULT_BRANCH_TOKEN ? "default branch" : p)).join(", ")
    : "none";

function Row({ label, children, mono = false }) {
  return (
    <div className="grid gap-x-4 sm:grid-cols-[11rem_1fr]">
      <dt className="text-muted-foreground">{label}</dt>
      <dd className={mono ? "font-mono text-xs break-all" : "break-words"}>{children}</dd>
    </div>
  );
}

/** The options of one trigger as a definition list. */
export function TriggerDetails({ trigger }) {
  return (
    <dl className="space-y-1 text-sm">
      {trigger.type === "push" ? (
        <>
          <Row label="Branches" mono>
            {list(trigger.branches?.include)}
          </Row>
          <Row label="Excluded branches" mono>
            {list(trigger.branches?.exclude)}
          </Row>
          <Row label="Tags">
            {trigger.tags?.enabled ? list(trigger.tags.include) : "Not scanned"}
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
            {(trigger.actions ?? []).map((a) => PR_ACTION_LABELS[a] ?? a).join(", ")}
          </Row>
          <Row label="Target branches" mono>
            {list(trigger.targetBranches?.include)}
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
            {trigger.cron}
          </Row>
          <Row label="Reads as">{describeCron(trigger.cron) ?? "—"}</Row>
          <Row label="Time zone" mono>
            {trigger.timezone}
          </Row>
          <Row label="Ref" mono>
            {trigger.ref === DEFAULT_BRANCH_TOKEN ? "default branch" : trigger.ref}
          </Row>
          <Row label="Scan kind">{trigger.scanKind === "full" ? "Full" : "Incremental"}</Row>
          <Row label="Missed runs">{trigger.missedPolicy === "run_once" ? "Run once" : "Skip"}</Row>
        </>
      ) : null}
      {trigger.type === "manual" ? (
        <Row label="Run now">Allowed for people who can run pipelines</Row>
      ) : null}
    </dl>
  );
}

function TriggerBlock({ trigger }) {
  return (
    <section
      aria-label={`${TRIGGER_LABELS[trigger.type]} trigger ${trigger.key}`}
      className="rounded-md border border-border p-3"
    >
      <h4 className="mb-2 flex items-center gap-2 text-sm font-medium">
        {TRIGGER_LABELS[trigger.type]}
        <span className="font-mono text-xs font-normal text-muted-foreground">{trigger.key}</span>
        <Badge tone={trigger.enabled ? "success" : "neutral"}>
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
        <div className="grid gap-3 lg:grid-cols-2">
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
        <dl className="space-y-1 text-sm">
          {scans.map(([type, scan]) => (
            <Row key={type} label={SCAN_LABELS[type]}>
              {scan?.enabled
                ? `On · engine ${scan.engine?.id ?? "default"}${scan.engine?.profile ? ` (${scan.engine.profile})` : ""} · threshold ${SEVERITY_LABELS[scan.severityThreshold] ?? scan.severityThreshold}`
                : "Off"}
            </Row>
          ))}
          <Row label="Excluded paths" mono>
            {list(config.exclusions?.paths)}
          </Row>
        </dl>
      </section>
      <section>
        <h3 className="mb-2 text-sm font-semibold">Execution controls</h3>
        <dl className="space-y-1 text-sm">
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
        </dl>
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

/** Diff table of two configurations; `previous` null means the first version. */
export function ConfigDiff({ previous, next, title }) {
  const rows = diffConfigs(previous, next);
  return (
    <section aria-label={title}>
      <h3 className="mb-2 text-sm font-semibold">{title}</h3>
      {rows.length === 0 ? (
        <p className="text-sm text-muted-foreground">No differences.</p>
      ) : (
        <div className="overflow-x-auto rounded-md border border-border">
          <table className="w-full text-left text-[13px] leading-5">
            <caption className="sr-only">{title}</caption>
            <thead className="border-b border-border text-muted-foreground">
              <tr>
                <th scope="col" className="px-3 py-2 font-medium">
                  Setting
                </th>
                <th scope="col" className="px-3 py-2 font-medium">
                  Change
                </th>
                <th scope="col" className="px-3 py-2 font-medium">
                  Before
                </th>
                <th scope="col" className="px-3 py-2 font-medium">
                  After
                </th>
              </tr>
            </thead>
            <tbody>
              {rows.map((r) => (
                <tr key={r.path} className="border-b border-border last:border-0">
                  <td className="px-3 py-1.5 font-mono text-xs break-all">{r.path}</td>
                  <td className="px-3 py-1.5">{KIND[r.kind]}</td>
                  <td className="px-3 py-1.5 font-mono text-xs break-all">{r.before ?? "—"}</td>
                  <td className="px-3 py-1.5 font-mono text-xs break-all">{r.after ?? "—"}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </section>
  );
}
