import { zodResolver } from "@hookform/resolvers/zod";
import { useImperativeHandle, useRef, useState } from "react";
import { Controller, useForm } from "react-hook-form";
import { toast } from "sonner";
import { Button } from "@/components/ui/button.jsx";
import { Select } from "@/components/ui/select.jsx";
import { Textarea } from "@/components/ui/textarea.jsx";
import { LIMITS, SEVERITY_LABELS } from "../constants/index.js";
import { describeActionError, useFindingAction } from "../hooks/use-findings.js";
import { decisionFormSchema } from "../schemas/forms.js";
import { newIdempotencyKey } from "../services/findings-service.js";
import { ConflictBanner, Field, describedBy } from "./form-bits.jsx";

const SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"];

/**
 * The review decision form (T-32 dialog and T-34 panel, SCREENS 6 and 7). Neither option is preselected and the AI advisory never
 * touches it (it is not rendered in here). Submitting records the decision for a lead's approval; a refused submit keeps every
 * typed character. `controlRef` lets T-34 drive it from the keyboard (`setDecision`, `focusRationale`, `submit`).
 * @param {{ workspaceId: string, finding: any, onDone: (finding: any) => void, onReload?: () => void,
 *   controlRef?: import("react").Ref<{ setDecision: (d: string) => void, focusRationale: () => void, submit: () => void }>,
 *   formId?: string, hideSubmit?: boolean, onSubmittingChange?: (pending: boolean) => void }} props
 */
export function DecisionForm({
  workspaceId,
  finding,
  onDone,
  onReload,
  controlRef,
  formId = "decision-form",
}) {
  const act = useFindingAction(workspaceId);
  const key = useRef(newIdempotencyKey());
  const [banner, setBanner] = useState(null);
  const {
    register,
    control,
    handleSubmit,
    watch,
    setValue,
    setFocus,
    setError,
    formState: { errors },
  } = useForm({
    resolver: zodResolver(decisionFormSchema),
    defaultValues: { decision: undefined, rationale: "", severityOverride: "" },
  });
  const decision = watch("decision");
  const rationale = watch("rationale") ?? "";
  const formRef = useRef(null);

  useImperativeHandle(
    controlRef,
    () => ({
      setDecision: (d) => setValue("decision", d, { shouldValidate: false }),
      focusRationale: () => setFocus("rationale"),
      submit: () => formRef.current?.requestSubmit(),
    }),
    [setValue, setFocus],
  );

  const submit = handleSubmit(async (values) => {
    setBanner(null);
    try {
      const body = {
        decision: values.decision,
        rationale: values.rationale,
        ...(values.decision === "true_positive" && values.severityOverride
          ? { severityOverride: values.severityOverride }
          : {}),
        expectedRev: finding.rev,
      };
      const result = await act.mutateAsync({
        run: (s) => s.createReview(finding.id, body, key.current),
      });
      key.current = newIdempotencyKey();
      onDone(result);
    } catch (error) {
      const { text, field, conflict } = describeActionError(error);
      if (conflict) setBanner({ text });
      else if (field && ["rationale", "severityOverride"].includes(field)) {
        setError(field, { message: text });
        setFocus(field);
      } else {
        setBanner({ text });
        toast.error(text);
      }
    }
  });

  const overrideOptions = SEVERITY_ORDER.filter((s) => s !== finding.toolSeverity);
  return (
    <form id={formId} ref={formRef} onSubmit={submit} noValidate className="space-y-4">
      {banner ? <ConflictBanner text={banner.text} onReload={onReload} /> : null}
      <fieldset
        className="space-y-2"
        aria-describedby={errors.decision ? `${formId}-decision-error` : undefined}
      >
        <legend className="text-sm font-medium">Your decision</legend>
        <div className="flex flex-wrap gap-x-6 gap-y-2">
          {[
            ["true_positive", "True positive", "T"],
            ["false_positive", "False positive", "F"],
          ].map(([value, label, hotkey]) => (
            <label key={value} className="flex items-center gap-2 text-sm">
              <input
                type="radio"
                value={value}
                aria-keyshortcuts={hotkey}
                className="size-4 accent-[var(--foreground)]"
                {...register("decision")}
              />
              {label}
            </label>
          ))}
        </div>
        {errors.decision ? (
          <p id={`${formId}-decision-error`} role="alert" className="text-xs text-status-danger">
            {errors.decision.message}
          </p>
        ) : null}
      </fieldset>

      <Field
        id={`${formId}-rationale`}
        label="Rationale"
        required
        hint={`${LIMITS.rationaleMin} to ${LIMITS.rationaleMax.toLocaleString()} characters. Plain text only.`}
        error={errors.rationale?.message}
        counter={{ value: rationale.length, max: LIMITS.rationaleMax }}
      >
        <Textarea
          id={`${formId}-rationale`}
          aria-keyshortcuts="R"
          rows={4}
          {...register("rationale")}
          {...describedBy(`${formId}-rationale`, true, errors.rationale?.message)}
        />
      </Field>

      <Field
        id={`${formId}-override`}
        label="Severity override"
        hint={
          decision === "true_positive"
            ? `Keep tool severity (${SEVERITY_LABELS[finding.toolSeverity]}) unless you have a reason.`
            : "Available when the decision is a true positive."
        }
        error={errors.severityOverride?.message}
      >
        <Controller
          control={control}
          name="severityOverride"
          render={({ field }) => (
            <Select
              id={`${formId}-override`}
              value={field.value}
              onChange={(e) => field.onChange(e.target.value)}
              disabled={decision !== "true_positive"}
              {...describedBy(`${formId}-override`, true, errors.severityOverride?.message)}
            >
              <option value="">{`Keep tool severity (${SEVERITY_LABELS[finding.toolSeverity]})`}</option>
              {overrideOptions.map((s) => (
                <option key={s} value={s}>
                  Change to {SEVERITY_LABELS[s]}
                </option>
              ))}
            </Select>
          )}
        />
      </Field>

      <p className="text-xs text-subtle-foreground">
        A lead who did not record this decision will approve it.
      </p>
      <div className="flex justify-end">
        <Button type="submit" disabled={act.isPending} aria-keyshortcuts="Control+Enter">
          {act.isPending ? "Submitting…" : "Submit for approval"}
        </Button>
      </div>
    </form>
  );
}
