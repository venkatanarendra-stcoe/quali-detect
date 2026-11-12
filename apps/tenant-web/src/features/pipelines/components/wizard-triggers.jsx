import { DEFAULT_BRANCH_TOKEN, PULL_REQUEST_ACTIONS, isKnownTimeZone } from "@qmentisai/shared";
import { Plus, Trash2 } from "lucide-react";
import { useMemo, useState } from "react";
import { ConfirmDialog } from "@/components/common/confirm-dialog.jsx";
import { Button } from "@/components/ui/button.jsx";
import { Input } from "@/components/ui/input.jsx";
import { Select } from "@/components/ui/select.jsx";
import {
  FORK_POLICY_LABELS,
  PR_ACTION_LABELS,
  TRIGGER_ICONS,
  pushTrigger,
  pullRequestTrigger,
  scheduleTrigger,
} from "../constants/index.js";
import { describeCron, previewFires } from "../schemas/index.js";
import { absoluteTime } from "./pipeline-bits.jsx";
import {
  Field,
  PatternListField,
  PatternTester,
  TriggerCard,
  errorsFor,
} from "./wizard-fields.jsx";

const indexOfType = (config, type) => config.triggers.findIndex((t) => t.type === type);
const timeZones = (() => {
  try {
    return ["UTC", ...Intl.supportedValuesOf("timeZone")];
  } catch {
    return ["UTC"];
  }
})();

const FORK_NOTE =
  "Fork PRs are untrusted. They never get secrets or integration credentials and cannot mark findings fixed. If GitHub does not say, a PR counts as a fork.";

/**
 * The fork policy control (SPEC §5.4.1, Q6). "Run without credentials" needs `pipeline.manage_fork_policy`: without it the
 * option is disabled with the reason and the control shows the current value; going back to "Do not run" needs only
 * `pipeline.manage`. Choosing it with permission asks for confirmation first.
 */
function ForkPolicy({ id, value, onChange, canForkPolicy, errors }) {
  const [confirming, setConfirming] = useState(false);
  const locked = !canForkPolicy;
  return (
    <div className="space-y-1.5">
      <Field id={id} label="Fork pull requests" errors={errors}>
        <Select
          id={id}
          value={value}
          aria-describedby={`${id}-note ${locked ? `${id}-lock` : ""}`}
          onChange={(e) => {
            if (e.target.value === "run_without_credentials") setConfirming(true);
            else onChange(e.target.value);
          }}
        >
          <option value="skip">{FORK_POLICY_LABELS.skip}</option>
          <option
            value="run_without_credentials"
            disabled={locked && value !== "run_without_credentials"}
          >
            {FORK_POLICY_LABELS.run_without_credentials}
          </option>
        </Select>
      </Field>
      <p id={`${id}-note`} className="text-xs text-subtle-foreground">
        {FORK_NOTE}
      </p>
      {locked ? (
        <p id={`${id}-lock`} className="text-xs text-muted-foreground">
          You need permission to allow fork pull requests to run, so only &quot;Do not run&quot; can
          be chosen.
        </p>
      ) : null}
      <ConfirmDialog
        open={confirming}
        onOpenChange={setConfirming}
        title="Let fork pull requests run without credentials?"
        description="Fork pull requests are untrusted. They run on a code archive only: no secrets, no integration credentials. Their results are marked untrusted, are never assigned automatically and cannot mark findings as fixed. This change is audited."
        confirmLabel="Allow without credentials"
        onConfirm={() => {
          onChange("run_without_credentials");
          setConfirming(false);
        }}
      />
    </div>
  );
}

function PushCard({ config, edit, errors, defaultBranch }) {
  const i = indexOfType(config, "push");
  const t = config.triggers[i];
  const p = `triggers.${i}`;
  const upd = (fn) =>
    edit((c) => {
      let k = indexOfType(c, "push");
      if (k < 0) k = c.triggers.push({ ...pushTrigger(), enabled: false }) - 1;
      fn(c.triggers[k]);
    });
  const toggle = () =>
    edit((c) => {
      const k = indexOfType(c, "push");
      if (k < 0) c.triggers.push(pushTrigger());
      else c.triggers[k].enabled = !c.triggers[k].enabled;
    });
  const view = t ?? { ...pushTrigger(), enabled: false };
  return (
    <TriggerCard
      id="trg-push"
      icon={TRIGGER_ICONS.push}
      title="Push"
      subtitle="Scan when commits are pushed to matching branches."
      enabled={Boolean(t?.enabled)}
      onToggle={toggle}
    >
      <PatternListField
        id="push-include"
        label="Branches to scan (one pattern per line)"
        hint={`Use * and ** wildcards. ${DEFAULT_BRANCH_TOKEN} means the repository's default branch.`}
        value={view.branches.include}
        onChange={(v) => upd((x) => (x.branches.include = v))}
        errors={errorsFor(errors, `${p}.branches.include`)}
      />
      <PatternListField
        id="push-exclude"
        label="Branches to ignore"
        value={view.branches.exclude}
        onChange={(v) => upd((x) => (x.branches.exclude = v))}
        errors={errorsFor(errors, `${p}.branches.exclude`)}
      />
      <PatternTester
        id="push-test"
        include={view.branches.include}
        exclude={view.branches.exclude}
        defaultBranch={defaultBranch}
      />
      <label className="flex items-center gap-2 text-sm">
        <input
          type="checkbox"
          checked={view.onBranchCreated === "run"}
          onChange={(e) => upd((x) => (x.onBranchCreated = e.target.checked ? "run" : "skip"))}
        />
        Scan new branches
      </label>
      <label className="flex items-center gap-2 text-sm">
        <input
          type="checkbox"
          checked={view.onForcePush === "run"}
          onChange={(e) => upd((x) => (x.onForcePush = e.target.checked ? "run" : "skip"))}
        />
        Scan force pushes
      </label>
      <label className="flex items-center gap-2 text-sm">
        <input
          type="checkbox"
          checked={view.tags.enabled}
          onChange={(e) => upd((x) => (x.tags.enabled = e.target.checked))}
        />
        Scan tags
      </label>
      {view.tags.enabled ? (
        <>
          <PatternListField
            id="push-tags-include"
            label="Tags to scan"
            value={view.tags.include}
            onChange={(v) => upd((x) => (x.tags.include = v))}
            errors={errorsFor(errors, `${p}.tags.include`)}
            placeholder="v*"
          />
          <PatternListField
            id="push-tags-exclude"
            label="Tags to ignore"
            value={view.tags.exclude}
            onChange={(v) => upd((x) => (x.tags.exclude = v))}
            errors={errorsFor(errors, `${p}.tags.exclude`)}
          />
        </>
      ) : null}
    </TriggerCard>
  );
}

function PullRequestCard({ config, edit, errors, defaultBranch, canForkPolicy }) {
  const i = indexOfType(config, "pull_request");
  const t = config.triggers[i];
  const p = `triggers.${i}`;
  const upd = (fn) =>
    edit((c) => {
      let k = indexOfType(c, "pull_request");
      if (k < 0) k = c.triggers.push({ ...pullRequestTrigger(), enabled: false }) - 1;
      fn(c.triggers[k]);
    });
  const view = t ?? { ...pullRequestTrigger(), enabled: false };
  return (
    <TriggerCard
      id="trg-pr"
      icon={TRIGGER_ICONS.pull_request}
      title="Pull request"
      subtitle="Scan when a pull request targets matching branches."
      enabled={Boolean(t?.enabled)}
      onToggle={() => upd((x) => (x.enabled = !x.enabled))}
    >
      <fieldset className="space-y-1.5">
        <legend className="text-sm font-medium">Pull request actions</legend>
        <div className="flex flex-wrap gap-x-4 gap-y-1">
          {PULL_REQUEST_ACTIONS.map((a) => (
            <label key={a} className="flex items-center gap-2 text-sm">
              <input
                type="checkbox"
                checked={view.actions.includes(a)}
                onChange={(e) =>
                  upd((x) => {
                    x.actions = e.target.checked
                      ? PULL_REQUEST_ACTIONS.filter((v) => x.actions.includes(v) || v === a)
                      : x.actions.filter((v) => v !== a);
                  })
                }
              />
              {PR_ACTION_LABELS[a]}
            </label>
          ))}
        </div>
        {errorsFor(errors, `${p}.actions`).map((m, k) => (
          <p key={k} role="alert" className="text-xs text-status-danger">
            {m}
          </p>
        ))}
      </fieldset>
      <PatternListField
        id="pr-include"
        label="Target branches (one pattern per line)"
        hint={`${DEFAULT_BRANCH_TOKEN} means the repository's default branch.`}
        value={view.targetBranches.include}
        onChange={(v) => upd((x) => (x.targetBranches.include = v))}
        errors={errorsFor(errors, `${p}.targetBranches.include`)}
      />
      <PatternListField
        id="pr-exclude"
        label="Target branches to ignore"
        value={view.targetBranches.exclude}
        onChange={(v) => upd((x) => (x.targetBranches.exclude = v))}
        errors={errorsFor(errors, `${p}.targetBranches.exclude`)}
      />
      <PatternTester
        id="pr-test"
        include={view.targetBranches.include}
        exclude={view.targetBranches.exclude}
        defaultBranch={defaultBranch}
      />
      <Field id="pr-drafts" label="Draft pull requests">
        <Select
          id="pr-drafts"
          value={view.drafts}
          onChange={(e) => upd((x) => (x.drafts = e.target.value))}
        >
          <option value="skip">Skip</option>
          <option value="run">Run</option>
        </Select>
      </Field>
      <ForkPolicy
        id="pr-fork"
        value={view.forkPolicy}
        canForkPolicy={canForkPolicy}
        onChange={(v) => upd((x) => (x.forkPolicy = v))}
        errors={errorsFor(errors, `${p}.forkPolicy`)}
      />
    </TriggerCard>
  );
}

function ScheduleCard({ index, trigger, edit, errors, limits, canRemove }) {
  const p = `triggers.${index}`;
  const upd = (fn) => edit((c) => fn(c.triggers[index]));
  const fires = useMemo(
    () =>
      isKnownTimeZone(trigger.timezone) ? previewFires(trigger.cron, trigger.timezone, 5) : [],
    [trigger.cron, trigger.timezone],
  );
  const human = describeCron(trigger.cron);
  const id = `sch-${index}`;
  return (
    <TriggerCard
      id={id}
      icon={TRIGGER_ICONS.schedule}
      title={`Schedule: ${trigger.key}`}
      subtitle={`Runs on a cron schedule. Runs must be at least ${Math.round(limits.scheduleMinIntervalSeconds / 60)} minutes apart.`}
      enabled={trigger.enabled}
      onToggle={() => upd((x) => (x.enabled = !x.enabled))}
      actions={
        canRemove ? (
          <Button
            variant="ghost"
            size="icon"
            aria-label={`Remove schedule ${trigger.key}`}
            onClick={() => edit((c) => c.triggers.splice(index, 1))}
          >
            <Trash2 aria-hidden="true" />
          </Button>
        ) : null
      }
    >
      <div className="grid gap-3 sm:grid-cols-2">
        <Field
          id={`${id}-key`}
          label="Key"
          hint="Lowercase letters, digits, - and _."
          errors={errorsFor(errors, `${p}.key`)}
        >
          <Input
            id={`${id}-key`}
            className="font-mono"
            value={trigger.key}
            onChange={(e) => upd((x) => (x.key = e.target.value))}
            autoComplete="off"
            spellCheck={false}
          />
        </Field>
        <Field
          id={`${id}-cron`}
          label="Cron expression"
          hint={
            human
              ? `Reads as: ${human}`
              : "Five fields: minute hour day-of-month month day-of-week."
          }
          errors={errorsFor(errors, `${p}.cron`)}
        >
          <Input
            id={`${id}-cron`}
            className="font-mono"
            value={trigger.cron}
            onChange={(e) => upd((x) => (x.cron = e.target.value))}
            aria-invalid={errorsFor(errors, `${p}.cron`).length > 0}
            autoComplete="off"
            spellCheck={false}
          />
        </Field>
        <Field id={`${id}-tz`} label="Time zone (IANA)" errors={errorsFor(errors, `${p}.timezone`)}>
          <Input
            id={`${id}-tz`}
            className="font-mono"
            list="tz-list"
            value={trigger.timezone}
            onChange={(e) => upd((x) => (x.timezone = e.target.value))}
            aria-invalid={errorsFor(errors, `${p}.timezone`).length > 0}
            autoComplete="off"
            spellCheck={false}
          />
        </Field>
        <Field
          id={`${id}-ref`}
          label="Ref to scan"
          hint={`${DEFAULT_BRANCH_TOKEN} is the default branch.`}
          errors={errorsFor(errors, `${p}.ref`)}
        >
          <Input
            id={`${id}-ref`}
            className="font-mono"
            value={trigger.ref}
            onChange={(e) => upd((x) => (x.ref = e.target.value))}
            autoComplete="off"
            spellCheck={false}
          />
        </Field>
        <Field id={`${id}-kind`} label="Scan kind">
          <Select
            id={`${id}-kind`}
            value={trigger.scanKind}
            onChange={(e) => upd((x) => (x.scanKind = e.target.value))}
          >
            <option value="full">Full</option>
            <option value="incremental">Incremental</option>
          </Select>
        </Field>
        <Field id={`${id}-missed`} label="Missed runs">
          <Select
            id={`${id}-missed`}
            value={trigger.missedPolicy}
            onChange={(e) => upd((x) => (x.missedPolicy = e.target.value))}
          >
            <option value="run_once">Run once when back</option>
            <option value="skip">Skip</option>
          </Select>
        </Field>
      </div>
      <div className="text-xs">
        <p className="font-medium">Next fire times (preview, {trigger.timezone})</p>
        {fires.length === 0 ? (
          <p className="text-muted-foreground">
            Enter a valid cron expression and time zone to see them.
          </p>
        ) : (
          <ol className="mt-1 space-y-0.5 text-muted-foreground">
            {fires.map((d) => (
              <li key={d.toISOString()} title={`UTC ${d.toISOString()}`}>
                {absoluteTime(d, {
                  dateStyle: "medium",
                  timeStyle: "short",
                  timeZone: trigger.timezone,
                  timeZoneName: "short",
                })}
              </li>
            ))}
          </ol>
        )}
        <p className="mt-1 text-subtle-foreground">
          The platform adds a small random delay to spread load, so the real run can start a few
          minutes later.
        </p>
      </div>
    </TriggerCard>
  );
}

function ManualCard({ config, edit }) {
  const i = indexOfType(config, "manual");
  const t = config.triggers[i];
  return (
    <TriggerCard
      id="trg-manual"
      icon={TRIGGER_ICONS.manual}
      title="Manual"
      subtitle="Allows Run now for people who may run pipelines."
      enabled={Boolean(t?.enabled)}
      onToggle={() =>
        edit((c) => {
          const k = indexOfType(c, "manual");
          if (k < 0) c.triggers.push({ key: "manual", type: "manual", enabled: true });
          else c.triggers[k].enabled = !c.triggers[k].enabled;
        })
      }
    >
      <p className="text-sm text-muted-foreground">
        A manual run asks for a branch or tag and queues one request.
      </p>
    </TriggerCard>
  );
}

/** Wizard step 2: one card per trigger type, with the schedule editor (cron, IANA time zone, next fire times). */
export function TriggersStep({ config, edit, errors, options, defaultBranch, canForkPolicy }) {
  const schedules = config.triggers
    .map((t, index) => ({ t, index }))
    .filter(({ t }) => t.type === "schedule");
  const max = options.limits.maxSchedulesPerPipeline;
  const addSchedule = () =>
    edit((c) => {
      let n = 1;
      while (c.triggers.some((t) => t.key === `schedule-${n}`)) n += 1;
      c.triggers.push(scheduleTrigger(`schedule-${n}`));
    });
  return (
    <div className="space-y-4">
      {(errors.triggers ?? []).map((m, i) => (
        <p key={i} role="alert" className="text-sm text-status-danger">
          {m}
        </p>
      ))}
      <PushCard config={config} edit={edit} errors={errors} defaultBranch={defaultBranch} />
      <PullRequestCard
        config={config}
        edit={edit}
        errors={errors}
        defaultBranch={defaultBranch}
        canForkPolicy={canForkPolicy}
      />
      {schedules.map(({ t, index }) => (
        <ScheduleCard
          key={index}
          index={index}
          trigger={t}
          edit={edit}
          errors={errors}
          limits={options.limits}
          canRemove
        />
      ))}
      <div>
        <Button variant="secondary" onClick={addSchedule} disabled={schedules.length >= max}>
          <Plus aria-hidden="true" /> Add schedule
        </Button>
        {schedules.length >= max ? (
          <p className="mt-1 text-xs text-muted-foreground">
            At most {max} schedules per pipeline.
          </p>
        ) : null}
      </div>
      <ManualCard config={config} edit={edit} />
      <datalist id="tz-list">
        {timeZones.map((z) => (
          <option key={z} value={z} />
        ))}
      </datalist>
    </div>
  );
}
