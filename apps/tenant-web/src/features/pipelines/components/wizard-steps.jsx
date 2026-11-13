import { PIPELINE_SCAN_TYPES, PIPELINE_SEVERITIES } from "@qmentisai/shared";
import { ShieldCheck } from "lucide-react";
import { Controller } from "react-hook-form";
import { Badge } from "@/components/ui/badge.jsx";
import { Input } from "@/components/ui/input.jsx";
import { Select } from "@/components/ui/select.jsx";
import { Switch } from "@/components/ui/switch.jsx";
import { Textarea } from "@/components/ui/textarea.jsx";
import { SCAN_HELP, SCAN_LABELS, SEVERITY_LABELS } from "../constants/index.js";
import { minutesOf } from "../schemas/index.js";
import { Field, PatternListField, errorsFor } from "./wizard-fields.jsx";

/** Step 1: repository (locked when editing or when opened from a repository), name, description, enable after creating. */
export function BasicsStep({
  form,
  repositories,
  repositoryLocked,
  repositoryName,
  editing,
  nameError,
}) {
  const { register, formState, watch, control } = form;
  const e = formState.errors;
  const repositoryId = watch("repositoryId");
  return (
    <div className="max-w-xl space-y-4">
      <Field
        id="pl-repository"
        label="Repository"
        errors={e.repositoryId ? [e.repositoryId.message] : []}
      >
        {repositoryLocked ? (
          <div
            className="flex h-9 items-center rounded-sm border border-input bg-secondary px-3 font-mono text-xs"
            id="pl-repository"
          >
            {repositoryName ?? repositoryId}
          </div>
        ) : (
          <Controller
            name="repositoryId"
            control={control}
            render={({ field }) => (
              <Select
                id="pl-repository"
                name={field.name}
                ref={field.ref}
                value={field.value ?? ""}
                onChange={(ev) => field.onChange(ev.target.value)}
                onBlur={field.onBlur}
                aria-invalid={Boolean(e.repositoryId)}
              >
                <option value="">Choose a repository</option>
                {repositories.map((r) => (
                  <option key={r.id} value={r.id}>
                    {r.fullName}
                  </option>
                ))}
              </Select>
            )}
          />
        )}
      </Field>
      {!repositoryLocked && repositories.length === 0 ? (
        <p className="text-xs text-muted-foreground">
          There is no active, enabled repository in this workspace to choose from.
        </p>
      ) : null}
      <Field
        id="pl-name"
        label="Name"
        hint="Unique on the repository, 1 to 100 characters."
        errors={[...(e.name ? [e.name.message] : []), ...(nameError ? [nameError] : [])]}
      >
        <Input
          id="pl-name"
          {...register("name")}
          maxLength={100}
          aria-invalid={Boolean(e.name || nameError)}
          autoComplete="off"
        />
      </Field>
      <Field
        id="pl-description"
        label="Description"
        hint="Optional, up to 500 characters."
        errors={e.description ? [e.description.message] : []}
      >
        <Textarea id="pl-description" {...register("description")} maxLength={500} />
      </Field>
      {!editing ? (
        <label className="flex items-center gap-2 text-sm">
          <input type="checkbox" {...register("enabled")} />
          Enable after creating
        </label>
      ) : null}
    </div>
  );
}

function ScanCard({ type, scan, engines, edit, errors }) {
  const id = `scan-${type}`;
  const p = `scans.${type}`;
  const upd = (fn) => edit((c) => fn(c.scans[type]));
  const engine = engines.find((x) => x.id === scan.engine.id);
  return (
    <section aria-labelledby={`${id}-title`} className="rounded-md border border-border bg-card">
      <header className="flex items-start justify-between gap-3 border-b border-border p-4">
        <div>
          <h3 id={`${id}-title`} className="text-sm font-semibold">
            {SCAN_LABELS[type]}
          </h3>
          <p className="mt-0.5 text-xs text-muted-foreground">{SCAN_HELP[type]}</p>
        </div>
        <Switch
          aria-labelledby={`${id}-title`}
          checked={scan.enabled}
          onCheckedChange={(v) => upd((x) => (x.enabled = v))}
        />
      </header>
      <div className={`grid gap-3 p-4 sm:grid-cols-3 ${scan.enabled ? "" : "opacity-60"}`}>
        <Field id={`${id}-engine`} label="Engine" errors={errorsFor(errors, `${p}.engine.id`)}>
          <Select
            id={`${id}-engine`}
            value={scan.engine.id}
            onChange={(e) =>
              upd((x) => {
                x.engine = { id: e.target.value };
              })
            }
          >
            {engines.map((en) => (
              <option key={en.id} value={en.id}>
                {en.name}
              </option>
            ))}
          </Select>
        </Field>
        <Field
          id={`${id}-profile`}
          label="Profile"
          errors={errorsFor(errors, `${p}.engine.profile`)}
        >
          <Select
            id={`${id}-profile`}
            value={scan.engine.profile ?? ""}
            disabled={!engine || engine.profiles.length === 0}
            onChange={(e) =>
              upd((x) => {
                if (e.target.value) x.engine.profile = e.target.value;
                else delete x.engine.profile;
              })
            }
          >
            <option value="">Engine default</option>
            {(engine?.profiles ?? []).map((pr) => (
              <option key={pr} value={pr}>
                {pr}
              </option>
            ))}
          </Select>
        </Field>
        <Field
          id={`${id}-sev`}
          label="Severity threshold"
          hint="Findings below it are not reported."
          errors={errorsFor(errors, `${p}.severityThreshold`)}
        >
          <Select
            id={`${id}-sev`}
            value={scan.severityThreshold}
            onChange={(e) => upd((x) => (x.severityThreshold = e.target.value))}
          >
            {PIPELINE_SEVERITIES.map((s) => (
              <option key={s} value={s}>
                {SEVERITY_LABELS[s]}
              </option>
            ))}
          </Select>
        </Field>
      </div>
    </section>
  );
}

/**
 * Step 3: scan shell. There is NO field for commands, scripts, install or build steps (R-8): scans read manifests and
 * lockfiles and never execute repository code. DAST and Asset Discovery are manual only and not selectable here.
 */
export function ScansStep({ config, edit, errors, options }) {
  return (
    <div className="space-y-4">
      <p className="flex items-start gap-2 rounded-md border border-border-strong bg-secondary p-3 text-sm">
        <ShieldCheck aria-hidden="true" className="mt-0.5 size-4 shrink-0 text-muted-foreground" />
        <span>
          Scans read manifests and lockfiles. They never install packages, run scripts or build your
          code.
        </span>
      </p>
      {errors.scans
        ? errors.scans.map((m, i) => (
            <p key={i} role="alert" className="text-sm text-status-danger">
              {m}
            </p>
          ))
        : null}
      {PIPELINE_SCAN_TYPES.map((type) => (
        <ScanCard
          key={type}
          type={type}
          scan={config.scans[type]}
          engines={options.engines[type] ?? []}
          edit={edit}
          errors={errors}
        />
      ))}
      <section
        aria-labelledby="manual-only"
        className="rounded-md border border-dashed border-border p-4"
      >
        <h3 id="manual-only" className="text-sm font-semibold">
          Manual-only scans: DAST and Asset Discovery
        </h3>
        <p className="mt-1 text-sm text-muted-foreground">
          Run on demand; never triggered automatically.
        </p>
        <ul className="mt-2 flex flex-wrap gap-2">
          {["DAST", "Asset Discovery"].map((n) => (
            <li key={n}>
              <Badge tone="neutral" aria-disabled="true" className="whitespace-normal">
                {n}: manual only (not available as a pipeline trigger)
              </Badge>
            </li>
          ))}
        </ul>
      </section>
      <PatternListField
        id="exclusions"
        label="Excluded paths (one pattern per line)"
        hint="Files matching these patterns are not scanned, for example vendor/** or **/*.min.js."
        value={config.exclusions.paths}
        onChange={(v) => edit((c) => (c.exclusions.paths = v))}
        errors={errorsFor(errors, "exclusions")}
      />
    </div>
  );
}

const SEVERITY_FAIL = ["none", "low", "medium", "high", "critical"];

/** Step 4: scan mode, timeouts, concurrency, cancellation and the fail policy. */
export function ControlsStep({ config, edit, errors, options }) {
  const { limits } = options;
  const ex = config.execution;
  const minutes = (seconds) => String(minutesOf(seconds));
  return (
    <div className="max-w-2xl space-y-5">
      <Field
        id="ctl-mode"
        label="Scan mode"
        hint="Incremental scans never mark findings as fixed. The first run, a changed scan configuration, new branches, force pushes and schedules run a full scan."
        errors={errorsFor(errors, "scanMode")}
      >
        <Select
          id="ctl-mode"
          value={config.scanMode.default}
          onChange={(e) => edit((c) => (c.scanMode.default = e.target.value))}
        >
          <option value="incremental">Incremental</option>
          <option value="full">Full</option>
        </Select>
      </Field>
      <div className="grid gap-3 sm:grid-cols-2">
        <Field
          id="ctl-timeout"
          label="Execution timeout (minutes)"
          hint={`Default ${minutesOf(limits.timeoutDefaultSeconds)}, platform maximum ${minutesOf(limits.timeoutMaxSeconds)}.`}
          errors={errorsFor(errors, "execution.timeoutSeconds")}
        >
          <Input
            id="ctl-timeout"
            type="number"
            min={minutesOf(limits.timeoutMinSeconds)}
            max={minutesOf(limits.timeoutMaxSeconds)}
            value={minutes(ex.timeoutSeconds)}
            onChange={(e) =>
              edit((c) => (c.execution.timeoutSeconds = Math.round(Number(e.target.value) * 60)))
            }
          />
        </Field>
        <Field
          id="ctl-task"
          label="Scan task timeout (minutes)"
          hint={`Default ${minutesOf(limits.scanTaskTimeoutDefaultSeconds)}, cannot exceed the execution timeout.`}
          errors={errorsFor(errors, "execution.scanTaskTimeoutSeconds")}
        >
          <Input
            id="ctl-task"
            type="number"
            min={Math.ceil(limits.scanTaskTimeoutMinSeconds / 60)}
            max={minutesOf(limits.timeoutMaxSeconds)}
            value={minutes(ex.scanTaskTimeoutSeconds)}
            onChange={(e) =>
              edit(
                (c) =>
                  (c.execution.scanTaskTimeoutSeconds = Math.round(Number(e.target.value) * 60)),
              )
            }
          />
        </Field>
        <Field
          id="ctl-conc"
          label="Concurrency"
          hint="What happens when a request arrives while another is in flight."
          errors={errorsFor(errors, "execution.concurrency.policy")}
        >
          <Select
            id="ctl-conc"
            value={ex.concurrency.policy}
            onChange={(e) => edit((c) => (c.execution.concurrency.policy = e.target.value))}
          >
            <option value="supersede">Supersede older requests</option>
            <option value="queue">Queue</option>
            <option value="skip">Skip the new request</option>
          </Select>
        </Field>
        {ex.concurrency.policy === "queue" ? (
          <Field
            id="ctl-queued"
            label="Maximum queued"
            hint={`Up to ${limits.maxQueuedPerPipeline}.`}
            errors={errorsFor(errors, "execution.concurrency.maxQueued")}
          >
            <Input
              id="ctl-queued"
              type="number"
              min={0}
              max={limits.maxQueuedPerPipeline}
              value={ex.concurrency.maxQueued}
              onChange={(e) =>
                edit((c) => (c.execution.concurrency.maxQueued = Number(e.target.value)))
              }
            />
          </Field>
        ) : null}
        <Field id="ctl-cancel" label="Cancellation">
          <Select
            id="ctl-cancel"
            value={ex.cancellation}
            onChange={(e) => edit((c) => (c.execution.cancellation = e.target.value))}
          >
            <option value="graceful">Graceful</option>
            <option value="immediate">Immediate</option>
          </Select>
        </Field>
      </div>
      <fieldset className="space-y-3 rounded-md border border-border p-4">
        <legend className="px-1 text-sm font-semibold">Fail the pipeline on</legend>
        <div className="grid gap-3 sm:grid-cols-3">
          <Field id="fail-sev" label="Severity" errors={errorsFor(errors, "failOn.severity")}>
            <Select
              id="fail-sev"
              value={config.failOn.severity}
              onChange={(e) => edit((c) => (c.failOn.severity = e.target.value))}
            >
              {SEVERITY_FAIL.map((s) => (
                <option key={s} value={s}>
                  {s === "none" ? SEVERITY_LABELS.none : `${SEVERITY_LABELS[s]} or higher`}
                </option>
              ))}
            </Select>
          </Field>
          <Field id="fail-scope" label="Findings">
            <Select
              id="fail-scope"
              value={config.failOn.scope}
              onChange={(e) => edit((c) => (c.failOn.scope = e.target.value))}
            >
              <option value="new">New findings only</option>
              <option value="all">All findings</option>
            </Select>
          </Field>
          <Field id="fail-engine" label="Engine errors">
            <Select
              id="fail-engine"
              value={config.failOn.onEngineError}
              onChange={(e) => edit((c) => (c.failOn.onEngineError = e.target.value))}
            >
              <option value="fail">Fail the run</option>
              <option value="ignore">Ignore</option>
            </Select>
          </Field>
        </div>
      </fieldset>
    </div>
  );
}
