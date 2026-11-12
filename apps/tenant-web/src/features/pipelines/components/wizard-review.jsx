import { FlaskConical } from "lucide-react";
import { Button } from "@/components/ui/button.jsx";
import { Input } from "@/components/ui/input.jsx";
import { WIZARD_STEPS, stepOfPath } from "../constants/index.js";
import { ConfigDiff, ConfigView } from "./config-view.jsx";
import { Field } from "./wizard-fields.jsx";

const STEP_LABEL = Object.fromEntries(WIZARD_STEPS.map((s) => [s.id, s.label]));

/**
 * Step 6 (Review): summary, validation result (each problem links back to its step), the Test triggers button, a change
 * note and the diff against the current version when editing.
 */
export function ReviewStep({
  form,
  config,
  issues,
  goTo,
  editing,
  currentVersion,
  previousConfig,
  onTest,
}) {
  const { register, formState } = form;
  return (
    <div className="space-y-5">
      <section aria-labelledby="validation-h">
        <h3 id="validation-h" className="mb-2 text-sm font-semibold">
          Validation
        </h3>
        {issues.length === 0 ? (
          <p role="status" className="text-sm text-status-success">
            The configuration is valid.
          </p>
        ) : (
          <ul role="alert" className="space-y-1 text-sm">
            {issues.map((issue, i) => {
              const step = stepOfPath(issue.path);
              return (
                <li key={`${issue.path}-${i}`} className="text-status-danger">
                  {issue.message}{" "}
                  <button
                    type="button"
                    onClick={() => goTo(step)}
                    className="rounded-sm text-foreground underline underline-offset-2 outline-none focus-visible:ring-2 focus-visible:ring-ring"
                  >
                    Fix in {STEP_LABEL[step]}
                  </button>
                </li>
              );
            })}
          </ul>
        )}
      </section>
      <div>
        <Button variant="secondary" onClick={onTest}>
          <FlaskConical aria-hidden="true" /> Test triggers
        </Button>
        <p className="mt-1 text-xs text-muted-foreground">
          Checks a sample push or pull request against the triggers above. Nothing is saved or run.
        </p>
      </div>
      {editing ? (
        <>
          <p className="text-sm">
            Saving creates version {currentVersion + 1}. Executions already requested keep version{" "}
            {currentVersion}.
          </p>
          <Field
            id="pl-note"
            label="Change note"
            hint="Optional, up to 200 characters. Shown in the version list."
            errors={formState.errors.changeNote ? [formState.errors.changeNote.message] : []}
          >
            <Input id="pl-note" {...register("changeNote")} maxLength={200} autoComplete="off" />
          </Field>
          {previousConfig ? (
            <ConfigDiff
              title={`Changes against version ${currentVersion}`}
              previous={previousConfig}
              next={config}
            />
          ) : null}
        </>
      ) : null}
      <ConfigView config={config} />
    </div>
  );
}
