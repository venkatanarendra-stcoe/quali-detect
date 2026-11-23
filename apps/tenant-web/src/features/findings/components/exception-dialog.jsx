import { zodResolver } from "@hookform/resolvers/zod";
import { useRef, useState } from "react";
import { Controller, useForm } from "react-hook-form";
import { toast } from "sonner";
import { Button } from "@/components/ui/button.jsx";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog.jsx";
import { Input } from "@/components/ui/input.jsx";
import { Textarea } from "@/components/ui/textarea.jsx";
import { useSession } from "@/features/auth/hooks/use-session.js";
import { useCan } from "@/features/authorization/hooks/use-permissions.js";
import { cn } from "@/lib/cn.js";
import { LIMITS } from "../constants/index.js";
import { describeActionError, useFindingAction } from "../hooks/use-findings.js";
import { dateInDays, exceptionFormSchema, expiryInstant } from "../schemas/forms.js";
import { newIdempotencyKey } from "../services/findings-service.js";
import { AssigneePicker } from "./action-dialogs.jsx";
import { SeverityBadge, StatusBadge, Untrusted } from "./finding-bits.jsx";
import { ConflictBanner, Field, InfoNote, describedBy } from "./form-bits.jsx";

const KIND_TEXT = {
  accept_risk:
    "Accepted risk is time-bound and requires approval by a lead. The finding stays visible and is reopened automatically when it expires.",
  suppress:
    "Suppression hides this finding only, in this pipeline. It requires approval, and you can set an expiry.",
};

/**
 * T-33: request accepted risk or suppression (SCREENS 5). One dialog, a two-option control at the top (an option the user may not
 * use is not offered), expiry required for accepted risk (1 to 180 days), optional for suppression (up to 365 days). The
 * requester can never approve it (SOD note). `initialKind` comes from the menu item that opened it.
 * @param {{ workspaceId: string, finding: any, initialKind: "accept_risk" | "suppress", onClose: () => void, onReload?: () => void }} props
 */
export function ExceptionDialog({ workspaceId, finding, initialKind, onClose, onReload }) {
  const can = useCan();
  const { me } = useSession();
  const act = useFindingAction(workspaceId);
  const key = useRef(newIdempotencyKey());
  const [banner, setBanner] = useState(null);
  const kinds = [
    can("finding.accept_risk") ? ["accept_risk", "Accepted risk"] : null,
    can("finding.suppress") ? ["suppress", "Suppression"] : null,
  ].filter(Boolean);
  const {
    register,
    control,
    handleSubmit,
    watch,
    setValue,
    setError,
    setFocus,
    formState: { errors },
  } = useForm({
    resolver: zodResolver(exceptionFormSchema),
    defaultValues: {
      kind: kinds.some(([k]) => k === initialKind) ? initialKind : (kinds[0]?.[0] ?? "accept_risk"),
      justification: "",
      compensatingControls: "",
      expiresAt: "",
      requestedApproverUserId: "",
    },
  });
  const kind = watch("kind");
  const justification = watch("justification") ?? "";
  const controls = watch("compensatingControls") ?? "";
  const expiresAt = watch("expiresAt");
  const maxDays = kind === "accept_risk" ? LIMITS.acceptRiskMaxDays : LIMITS.suppressMaxDays;
  const presets = kind === "accept_risk" ? [30, 90, 180] : [30, 90, 365];

  const submit = handleSubmit(async (v) => {
    setBanner(null);
    try {
      await act.mutateAsync({
        run: (s) =>
          s.createException(
            finding.id,
            {
              kind: v.kind,
              justification: v.justification,
              ...(v.kind === "accept_risk" && v.compensatingControls
                ? { compensatingControls: v.compensatingControls }
                : {}),
              ...(v.expiresAt ? { expiresAt: expiryInstant(v.expiresAt) } : {}),
              ...(v.requestedApproverUserId
                ? { requestedApproverUserId: v.requestedApproverUserId }
                : {}),
              expectedRev: finding.rev,
            },
            key.current,
          ),
      });
      toast.success("Request submitted for approval");
      onClose();
    } catch (error) {
      const { text, field, conflict } = describeActionError(error);
      if (
        !conflict &&
        field &&
        ["justification", "compensatingControls", "expiresAt"].includes(field)
      ) {
        setError(field, { message: text });
        setFocus(field);
      } else setBanner({ text, conflict });
    }
  });

  return (
    <Dialog open onOpenChange={(open) => (!open ? onClose() : undefined)}>
      <DialogContent className="max-sm:top-0 max-sm:left-0 max-sm:h-dvh max-sm:max-h-none max-sm:w-full max-sm:max-w-none max-sm:translate-x-0 max-sm:translate-y-0 max-sm:rounded-none">
        <DialogHeader>
          <DialogTitle>
            {kind === "suppress" ? "Request suppression" : "Request accepted risk"}
          </DialogTitle>
          <DialogDescription>{KIND_TEXT[kind]}</DialogDescription>
        </DialogHeader>
        <form onSubmit={submit} noValidate className="space-y-4">
          {banner ? (
            <ConflictBanner text={banner.text} onReload={banner.conflict ? onReload : undefined} />
          ) : null}

          <div className="flex flex-wrap items-center gap-2 rounded-md border border-border bg-card px-3 py-2 text-sm">
            <SeverityBadge severity={finding.severity} />
            <Untrusted className="min-w-0 flex-1 font-medium">{finding.title}</Untrusted>
            <StatusBadge status={finding.status} />
          </div>

          {kinds.length > 1 ? (
            <div
              role="radiogroup"
              aria-label="Request type"
              className="inline-flex rounded-md border border-border-strong p-0.5"
            >
              {kinds.map(([value, label]) => (
                <button
                  key={value}
                  type="button"
                  role="radio"
                  aria-checked={kind === value}
                  onClick={() => {
                    setValue("kind", value);
                    setValue("expiresAt", "");
                  }}
                  className={cn(
                    "rounded-sm px-3 py-1 text-sm font-medium outline-none focus-visible:ring-2 focus-visible:ring-ring",
                    kind === value
                      ? "bg-secondary text-foreground"
                      : "text-muted-foreground hover:text-foreground",
                  )}
                >
                  {label}
                </button>
              ))}
            </div>
          ) : null}

          <Field
            id="exc-justification"
            label="Risk statement / justification"
            required
            hint={`${LIMITS.justificationMin} to ${LIMITS.justificationMax.toLocaleString()} characters. Plain text only.`}
            error={errors.justification?.message}
            counter={{ value: justification.length, max: LIMITS.justificationMax }}
          >
            <Textarea
              id="exc-justification"
              rows={4}
              {...register("justification")}
              {...describedBy("exc-justification", true, errors.justification?.message)}
            />
          </Field>

          {kind === "accept_risk" ? (
            <Field
              id="exc-controls"
              label="Compensating controls (optional)"
              error={errors.compensatingControls?.message}
              counter={{ value: controls.length, max: LIMITS.compensatingControlsMax }}
            >
              <Textarea
                id="exc-controls"
                rows={2}
                {...register("compensatingControls")}
                {...describedBy("exc-controls", false, errors.compensatingControls?.message)}
              />
            </Field>
          ) : null}

          <Field
            id="exc-expiry"
            label={kind === "accept_risk" ? "Expiry date" : "Expiry date (optional)"}
            required={kind === "accept_risk"}
            hint={`Format YYYY-MM-DD, from tomorrow to ${maxDays} days.${kind === "suppress" ? " Leave empty for no expiry." : ""}`}
            error={errors.expiresAt?.message}
          >
            <div className="flex flex-wrap items-center gap-2">
              <Input
                id="exc-expiry"
                type="date"
                className="w-44"
                min={dateInDays(1)}
                max={dateInDays(maxDays)}
                {...register("expiresAt")}
                {...describedBy("exc-expiry", true, errors.expiresAt?.message)}
              />
              {presets.map((days) => (
                <Button
                  key={days}
                  type="button"
                  size="sm"
                  variant="secondary"
                  aria-pressed={expiresAt === dateInDays(days)}
                  onClick={() => setValue("expiresAt", dateInDays(days), { shouldValidate: true })}
                >
                  {days} days
                </Button>
              ))}
              {kind === "suppress" ? (
                <Button
                  type="button"
                  size="sm"
                  variant="ghost"
                  onClick={() => setValue("expiresAt", "")}
                >
                  No expiry
                </Button>
              ) : null}
            </div>
          </Field>

          <Field
            id="exc-approver"
            label="Requested approver (optional)"
            hint="Any eligible lead can decide; this only notifies your choice."
          >
            <Controller
              control={control}
              name="requestedApproverUserId"
              render={({ field }) => (
                <AssigneePicker
                  id="exc-approver"
                  label="Requested approver"
                  workspaceId={workspaceId}
                  value={field.value}
                  onChange={field.onChange}
                  excludeUserId={me?.user?.id}
                  placeholder="Any eligible lead"
                  describedby="exc-approver-hint"
                />
              )}
            />
          </Field>

          <InfoNote>
            You can&apos;t approve your own request. A different person with approval rights
            decides.
          </InfoNote>

          <DialogFooter>
            <Button type="button" variant="ghost" onClick={onClose}>
              Cancel
            </Button>
            <Button type="submit" disabled={act.isPending || kinds.length === 0}>
              {act.isPending ? "Submitting…" : "Submit for approval"}
            </Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  );
}
